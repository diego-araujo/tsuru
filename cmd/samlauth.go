// Copyright 2015 tsuru authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"html/template"
)

const formPostPage = `<!DOCTYPE html>
<html>
<head>
	<style>
	body {
		display: none;
	}
	</style>
</head>
<body onload="document.frm.submit()">
	<form method="POST" name="frm" action="{{.URL}}">
		<input type="hidden" name="SAMLRequest" value="{{.SAMLRequest}}" />
		<input type="submit" value="Go to login" />
	</form>
</body>
</html>
`



func requestId(schemeData map[string]string) string {
	p := schemeData["ID"]

	return fmt.Sprintf("%s", p)

}


func requestToken(id string) (string, error) {
	var token string
	params := map[string]string{"id": id}
	u, err := GetURL("/auth/login")
	if err != nil {
		return token, fmt.Errorf("Error in GetURL: %s", err.Error())
	}
	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(params)
	if err != nil {
		return token, fmt.Errorf("Error encoding params %#v: %s", params, err.Error())
	}
	resp, err := http.Post(u, "application/json", &buf)
	if err != nil {
		return token, fmt.Errorf("Error during login post: %s", err.Error())
	}
	defer resp.Body.Close()
	result, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return token, fmt.Errorf("Error reading body: %s", err.Error())
	}
	data := make(map[string]interface{})
	err = json.Unmarshal(result, &data)
	if err != nil {
		return token, fmt.Errorf("Error parsing response: %s - %s", result, err.Error())
	}
	return data["token"].(string), nil
}

func samlPreLogin(schemeData map[string]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {	
		t := template.New("saml")
		t, err := t.Parse(formPostPage)
		if err != nil {
			page := fmt.Sprintf(errorMarkup)
			w.Header().Add("Content-Type", "text/html")
			w.Write([]byte(page))
		}else {
			t.Execute(w, schemeData)
		}
	}
}

func (c *login) samlLogin(context *Context, client *Client) error {
	
	schemeData := c.getScheme().Data

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		return err
	}

	preLoginUrl := fmt.Sprintf("http://localhost:%s/", port)
	http.HandleFunc("/", samlPreLogin(schemeData))
	server := &http.Server{}
	go server.Serve(l)
	err = open(preLoginUrl)
	if err != nil {
		fmt.Fprintln(context.Stdout, "Failed to start your browser.")
		fmt.Fprintf(context.Stdout, "Please open the following URL in your browser: %s\n", preLoginUrl)
	}
	
	requestId := requestId(schemeData)
	token, err := requestToken(requestId)
	if err == nil {
		writeToken(token)
	}
	fmt.Fprintln(context.Stdout, "Successfully logged in!")
	return nil
}
