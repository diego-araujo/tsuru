// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package samlauth

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/tsuru/config"
	"github.com/tsuru/tsuru/auth"
	"github.com/tsuru/tsuru/auth/native"
	"github.com/tsuru/tsuru/errors"
	"github.com/tsuru/tsuru/log"
	"golang.org/x/net/context"
	"github.com/diego-araujo/go-saml"
)

var (
	ErrMissingRequestIdError       = &errors.ValidationError{Message: "You must provide RequestID to login"}
	ErrMissingFormValueError       = &errors.ValidationError{Message: "SAMLResponse form value missing"}
	ErrParseResponseError       = &errors.ValidationError{Message: "SAMLResponse parse error"}

)

type SAMLAuthParser interface {
	Parse(infoResponse *http.Response) (string, error)
}

type SAMLAuthScheme struct {
	BaseConfig   {		EntityID string,
						PublicCert string,
						PrivateKey string,
						CallbackPath string
						CallbackPort int,
						IdpUrl string,
						IdpDescriptorUrl string,
						IdpPublicCert string,

						SignRequest bool,
						SignResponse bool
	}
	
	Parser       SAMLAuthParser
}

func init() {
	auth.RegisterScheme("samlauth", &SAMLAuthScheme{})
}

// This method loads basic config and returns a copy of the
// config object.
func (s *SAMLAuthScheme) loadConfig() (samlauth.Config, error) {
	if s.BaseConfig.EntityID != "" {
		return s.BaseConfig, nil
	}
	if s.Parser == nil {
		s.Parser = s
	}
	var emptyConfig samlauth.Config
	publicCert, err := config.GetString("auth:samlauth:sp-publiccert")
	if err != nil {
		return emptyConfig, err
	}
	privateKey, err := config.GetString("auth:samlauth:sp-privatekey")
	if err != nil {
		return emptyConfig, err
	}
	idpUrl, err := config.GetString("auth:samlauth:idp-ssourl")
	if err != nil {
		return emptyConfig, err
	}
	idpDescriptorUrl, err := config.GetString("auth:samlauth:idp-ssodescriptorurl")
	if err != nil {
		return emptyConfig, err
	}
	idpPublicCert, err := config.GetString("auth:samlauth:idp-publiccert")
	if err != nil {
		return emptyConfig, err
	}
	infoURL, err := config.GetString("auth:samlauth:callback-path")
	if err != nil {
		return emptyConfig, err
	}
	callbackPort, err := config.GetInt("auth:samlauth:callback-port")
	if err != nil {
		log.Debugf("auth:samlauth:callback-port not found using random port: %s", err)
	}

	entityId, err := config.GetInt("auth:samlauth:sp-entityid")
	if err != nil {
		return emptyConfig, err
	}

	signRequest, err := config.GetBoll("auth:samlauth:sign-request")
	if err != nil {
		return emptyConfig, err
	}

	signResponse, err := config.GetBoll("auth:samlauth:idp-signresponse")
	if err != nil {
		return emptyConfig, err
	}
	
	s.BaseConfig = s.BaseConfig{
		EntityID:     		entityId,
		PublicCert:   		publicCert,
		PrivateKey:   		privateKey,
		CallbackPath: 		callbackPath,
		CallbackPort: 		callbackPort,
		IdpUrl:		  		idpUrl,
		IdpDescriptorUrl: 	idpDescriptorUrl,
		IdpPublicCert: 		idpPublicCert,
		SignRequest: 		signRequest,
		SignResponse: 		signResponse,
	}
	return s.BaseConfig, nil
}

func (s *SAMLAuthScheme) Login(params map[string]string) (auth.Token, error) {
	config, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	requestId, ok := params["ID"]
	if !ok {
		return nil, ErrMissingRequestIdError
	}
	
	return
}



func (s *SAMLAuthScheme) handleToken(t *oauth2.Token) (*Token, error) {
	if t.AccessToken == "" {
		return nil, ErrEmptyAccessToken
	}
	conf, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	client := conf.Client(context.Background(), t)
	response, err := client.Get(s.InfoUrl)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	email, err := s.Parser.Parse(response)
	if email == "" {
		return nil, ErrEmptyUserEmail
	}
	user, err := auth.GetUserByEmail(email)
	if err != nil {
		if err != auth.ErrUserNotFound {
			return nil, err
		}
		registrationEnabled, _ := config.GetBool("auth:user-registration")
		if !registrationEnabled {
			return nil, err
		}
		user = &auth.User{Email: email}
		err := user.Create()
		if err != nil {
			return nil, err
		}
	}
	token := Token{*t, email}
	err = token.save()
	if err != nil {
		return nil, err
	}
	return &token, nil
}

func (s *SAMLAuthScheme) AppLogin(appName string) (auth.Token, error) {
	nativeScheme := native.NativeScheme{}
	return nativeScheme.AppLogin(appName)
}

func (s *SAMLAuthScheme) Logout(token string) error {
	return deleteToken(token)
}

func (s *SAMLAuthScheme) Auth(header string) (auth.Token, error) {
	token, err := getToken(header)
	if err != nil {
		nativeScheme := native.NativeScheme{}
		token, nativeErr := nativeScheme.Auth(header)
		if nativeErr == nil && token.IsAppToken() {
			return token, nil
		}
		return nil, err
	}
	config, err := s.loadConfig()
	if err != nil {
		return nil, err
	}
	client := config.Client(context.Background(), &token.Token)
	rsp, err := client.Get(s.InfoUrl)
	if err != nil {
		return nil, err
	}
	defer rsp.Body.Close()
	return token, nil
}

func (s *SAMLAuthScheme) Name() string {
	return "samlauth"
}

func generateAuthnRequest() (interface{}, error) {

	sp := createSP()

	// generate the AuthnRequest and then get a base64 encoded string of the XML
	authnRequest := sp.GetAuthnRequest()


	//b64XML, err := authnRequest.String(authnRequest)
	b64XML, err := authnRequest.CompressedEncodedSignedString(sp.PrivateKeyPath)
	//b64XML, err := authnRequest.EncodedSignedString(sp.PrivateKeyPath)
	if err != nil {
		return nil, err
	}

	// for convenience, get a URL formed with the SAMLRequest parameter
	url, err := saml.GetAuthnRequestURL(sp.IDPSSOURL, b64XML, sp.AssertionConsumerServiceURL)
	if err != nil {
		return nil, err
	}

	data := struct {
		Base64AuthRequest string
		URL               string,
		ID 				  string,
	}{
		Base64AuthRequest: b64XML,
		URL:               url,
		ID:				   authnRequest.ID
	}

	return data, nil
}

func createSP() *saml.ServiceProviderSettings {
	config, err := s.loadConfig()
		if err != nil {
			return nil, err
		}
	sp := saml.ServiceProviderSettings{
		PublicCertPath: 		config.PublicCert,
		PrivateKeyPath: config.PrivateKey,
		IDPSSOURL:		config.IdpUrl,
		IDPSSODescriptorURL:	config.IdpDescriptorUrl,
		IDPPublicCertPath:   config.IdpPublicCert,
		Id:					config.EntityID,
		SPSignRequest:               config.SignRequest,
		IDPSignResponse:             config.SignResponse,
		AssertionConsumerServiceURL: "http://dsu20a.cce.usp.br:8000/callback",
	}
	sp.Init()

	return &sp
}


func (s *SAMLAuthScheme) Info() (auth.SchemeInfo, error) {
	config, err := s.loadConfig()
	if err != nil {
		return nil, err
	}

	authnRequest, err = generateAuthnRequest()
	if err != nil {
		return nil, err
	}

	//persist request in database
	s := newSamlRequest(authnRequest.ID)
	err := s.Save()
	if err != nil {
		return nil, err
	}
	return auth.SchemeInfo{"ID":authnRequest.ID,"SAMLRequest": authnRequest.Base64AuthRequest, "URL":authnRequest.URL}, nil
}

func (s *SAMLAuthScheme) Parse(r *http.Request) (string, error) {
	user := struct {
		Email string `json:"email"`
	}{}
		
	encodedXML := r.FormValue("SAMLResponse")

	if encodedXML == "" {
		return user.Email, ErrMissingFormValueError
	}
	

	response, err := ParseEncodedResponse(encodedXML)
	//  response, err := saml. ParseCompressedEncodedResponse(encodedXML)
	if err != nil {

		return user.Email, &ErrParseResponseError{Message: "SAMLResponse parse error: "+err.Error()}
	}

	sp := createSP()
	response.Decrypt(sp.PrivateKeyPath)

	//If is a encrypted response need decode
	if response.IsEncrypted() {
		err = response.Decrypt(sp.PrivateKeyPath)
		if err != nil {
			http.Error(w, "SAMLResponse parse: "+err.Error(), 500)
			return
		}
	}

	fmt.Printf("\n\n\n")
	fmt.Printf(response.String())
	fmt.Printf(response.ID)
	login, err := getUserIdentifierLogin(response)

}

func (s *SAMLAuthScheme) Create(user *auth.User) (*auth.User, error) {
	user.Password = ""
	err := user.Create()
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (s *SAMLAuthScheme) Remove(u *auth.User) error {
	err := deleteAllTokens(u.Email)
	if err != nil {
		return err
	}
	return u.Delete()
}
