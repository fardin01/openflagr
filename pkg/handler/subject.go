package handler

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/openflagr/flagr/pkg/config"
	"github.com/openflagr/flagr/pkg/util"

	jwt "github.com/form3tech-oss/jwt-go"
)

func getSubjectFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	if config.Config.JWTAuthEnabled {
		token, ok := r.Context().Value(config.Config.JWTAuthUserProperty).(*jwt.Token)
		if !ok {
			return ""
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			return util.SafeString(claims[config.Config.JWTAuthUserClaim])
		}

	} else if config.Config.HeaderAuthEnabled {
		// https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html
		if config.Config.HeaderAuthUserFieldAwsAlb {
			encodedJwt := r.Header.Get("x-amzn-oidc-data")
			jwtPayload := strings.Split(encodedJwt, ".")[1]
			rawData, err := base64.StdEncoding.DecodeString(jwtPayload)
			if err != nil {
				fmt.Println("Error decoding base64 x-amzn-oidc-data header:", err)
				return ""
			}

			var jsonMap map[string]interface{}
			err = json.Unmarshal(rawData, &jsonMap)
			if err != nil {
				fmt.Println("Error unmarshaling JSON:", err)
				return ""
			}

			return jsonMap["email"].(string)
		} else {
			return r.Header.Get(config.Config.HeaderAuthUserField)
		}
	}

	return ""
}
