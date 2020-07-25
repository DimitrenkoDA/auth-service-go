// +heroku install cmd/main.go

module github.com/DimitrenkoDA/auth-service-go

go 1.13

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gorilla/mux v1.7.4
	github.com/nu7hatch/gouuid v0.0.0-20131221200532-179d4d0c4d8d
	go.mongodb.org/mongo-driver v1.3.5
	golang.org/x/crypto v0.0.0-20190530122614-20be4c3c3ed5
)
