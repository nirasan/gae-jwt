package app

import (
	"net/http"
	"github.com/nirasan/gae-jwt/handler"
)

func init() {
	http.Handle("/", handler.NewHandler())
}
