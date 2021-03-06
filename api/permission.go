package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/tsuru/tsuru/auth"
	"github.com/tsuru/tsuru/permission"
)

func addRole(w http.ResponseWriter, r *http.Request, t auth.Token) error {
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	var params map[string]string
	err = json.Unmarshal(b, &params)
	_, err = permission.NewRole(params["name"], params["context"])
	return err
}

func removeRole(w http.ResponseWriter, r *http.Request, t auth.Token) error {
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	var params map[string]string
	err = json.Unmarshal(b, &params)
	return permission.DestroyRole(params["name"])
}

func listRoles(w http.ResponseWriter, r *http.Request, t auth.Token) error {
	roles, err := permission.ListRoles()
	if err != nil {
		return err
	}
	b, err := json.Marshal(roles)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func addPermissions(w http.ResponseWriter, r *http.Request, t auth.Token) error {
	roleName := r.URL.Query().Get(":name")
	role, err := permission.FindRole(roleName)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	var params map[string][]string
	err = json.Unmarshal(b, &params)
	if err != nil {
		return err
	}
	return role.AddPermissions(params["permissions"]...)
}

func removePermissions(w http.ResponseWriter, r *http.Request, t auth.Token) error {
	roleName := r.URL.Query().Get(":name")
	role, err := permission.FindRole(roleName)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	var params map[string][]string
	err = json.Unmarshal(b, &params)
	if err != nil {
		return err
	}
	return role.RemovePermissions(params["permissions"]...)
}
