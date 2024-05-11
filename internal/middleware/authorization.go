package middleware

import (
	"errors"
	"net/http"

	"github.com/Kerlenton/goapi/api"
	"github.com/Kerlenton/goapi/internal/tools"
	log "github.com/sirupsen/logrus"
)

var UnAthorizedError = errors.New("Invalid username or token.")

func Authorization(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var username string = r.URL.Query().Get("username")
		var token = r.Header.Get("Authorization")
		var err error

		if username == "" || token == "" {
			log.Error(UnAthorizedError)
			api.RequestErrorHandler(w, UnAthorizedError)
			return
		}

		var database *tools.DatabaseInterface
		database, err = tools.NewDatabase()
		if err != nil {
			api.InternalErrorHandler(w)
			return
		}

		var loginDetails *tools.LoginDetails
		loginDetails = (*database).GetUserLoginDetails(username)

		if loginDetails == nil || token != (*loginDetails).AuthToken {
			log.Error(UnAthorizedError)
			api.RequestErrorHandler(w, UnAthorizedError)
			return
		}

		next.ServeHTTP(w, r)
	})
}
