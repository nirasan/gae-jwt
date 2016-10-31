package handler

import (
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/appengine"
	"google.golang.org/appengine/aetest"
	"google.golang.org/appengine/datastore"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegistrationHandler(t *testing.T) {

	// aetest (App Engine Test) のインスタンス作成
	opt := aetest.Options{StronglyConsistentDatastore: true}
	instance, err := aetest.NewInstance(&opt)
	if err != nil {
		t.Fatalf("Failed to create aetest instance: %v", err)
	}
	defer instance.Close()

	// aetest インスタンスからリクエストの作成
	req, _ := instance.NewRequest("POST", "/registration", strings.NewReader(`{"username":"user1", "password":"pass1"}`))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスの作成
	res := httptest.NewRecorder()

	// コンテキストの取得
	ctx := appengine.NewContext(req)

	// リクエストの実行
	RegistrationHandler(res, req)

	// レスポンスのステータスコード検証
	if res.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "200", res.Code)
	}

	// Datastore の検証
	var userAuthentication UserAuthentication
	var key *datastore.Key

	// 作成していないユーザーが存在していない
	key = datastore.NewKey(ctx, "UserAuthentication", "user2", 0, nil)
	if err := datastore.Get(ctx, key, &userAuthentication); err != datastore.ErrNoSuchEntity {
		t.Error("user already exist")
	}

	// 作成したユーザーが存在する
	key = datastore.NewKey(ctx, "UserAuthentication", "user1", 0, nil)
	if err := datastore.Get(ctx, key, &userAuthentication); err != nil {
		t.Error("user not found")
	}
}

func TestAuthenticationHandler(t *testing.T) {

	// aetest (App Engine Test) のインスタンス作成
	opt := aetest.Options{StronglyConsistentDatastore: true}
	instance, err := aetest.NewInstance(&opt)
	if err != nil {
		t.Fatalf("Failed to create aetest instance: %v", err)
	}
	defer instance.Close()

	// aetest インスタンスからリクエストの作成
	req, _ := instance.NewRequest("POST", "/authentication", strings.NewReader(`{"username":"user1", "password":"pass1"}`))
	req.Header.Set("Content-Type", "application/json")

	// レスポンスの作成
	res := httptest.NewRecorder()

	// コンテキストの取得
	ctx := appengine.NewContext(req)

	// ユーザーを事前に作成
	key := datastore.NewKey(ctx, "UserAuthentication", "user1", 0, nil)
	pass, _ := bcrypt.GenerateFromPassword([]byte("pass1"), bcrypt.DefaultCost)
	if _, err := datastore.Put(ctx, key, &UserAuthentication{Username: "user1", Password: string(pass)}); err != nil {
		t.Fatal(err)
	}

	// リクエストの実行
	AuthenticationHandler(res, req)

	// レスポンスのステータスコード検証
	if res.Code != http.StatusOK {
		t.Fatalf("Non-expected status code%v:\n\tbody: %v", "200", res.Code)
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}

	var authenticationHandlerResponse AuthenticationHandlerResponse
	if err := json.Unmarshal(body, &authenticationHandlerResponse); err != nil {
		t.Fatal(err)
	}

	if !authenticationHandlerResponse.Success {
		t.Error("response failure", authenticationHandlerResponse)
	}

	if len(authenticationHandlerResponse.Token) <= 0 {
		t.Error("empty token")
	}
}
