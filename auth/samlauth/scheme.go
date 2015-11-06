// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package samlauth


type ServiceProviderSettings struct {
	PublicCertPath              string
	PrivateKeyPath              string
	IDPSSOURL                   string
	IDPSSODescriptorURL         string
	IDPPublicCertPath           string
	AssertionConsumerServiceURL string
	Id                          string
  	SPSignRequest               bool
	IDPSignResponse				bool
	hasInit                     bool
	publicCert                  string
	privateKey                  string
	iDPPublicCert               string
}