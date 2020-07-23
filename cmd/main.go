package main

import (
	"context"

	uuid "github.com/nu7hatch/gouuid"

	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"time"

	"github.com/DimitrenkoDA/auth-service-go/helper"
	"github.com/DimitrenkoDA/auth-service-go/models"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

const addr = ":8000"

func UnprocessableEntity(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusUnprocessableEntity)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}

func BadRequest(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusBadRequest)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}

func InternalServerError(w http.ResponseWriter, err error) {
	w.WriteHeader(http.StatusInternalServerError)

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": err.Error(),
	})
}

func Ok(w http.ResponseWriter, body interface{}) {
	w.Header().Set("Content-Type", "application/json")

	if body == nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	_ = json.NewEncoder(w).Encode(body)
}

func HashRefreshToken(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckHashRefreshToken(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func generateTokenPair(userID primitive.ObjectID) (map[string]string, error) {
	accessToken := jwt.New(jwt.SigningMethodHS512)

	newUuid, err := uuid.NewV4()
	if err != nil {
		return nil, err
	}

	claims := accessToken.Claims.(jwt.MapClaims)
	claims["uuid"] = newUuid.String()
	claims["user_id"] = userID
	claims["exp"] = time.Now().Add(time.Minute * 1).Unix()

	t, err := accessToken.SignedString([]byte("access_secret"))
	if err != nil {
		return nil, err
	}

	refreshToken := jwt.New(jwt.SigningMethodHS256)
	rtClaims := refreshToken.Claims.(jwt.MapClaims)
	rtClaims["access_token_uuid"] = newUuid.String()
	rtClaims["user_id"] = userID
	rtClaims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	rt, err := refreshToken.SignedString([]byte("refresh_secret"))
	if err != nil {
		return nil, err
	}

	baseRefreshToken, err := HashRefreshToken(rt)
	if err != nil {
		return nil, err
	}

	var token models.Token
	token.UserID = userID
	token.AccessTokenUUID = newUuid.String()
	token.Data = baseRefreshToken

	collection := helper.ConnectionDB()
	result, err := collection.InsertOne(context.TODO(), token)
	if err != nil {
		return nil, err
	}

	log.Println(result)

	return map[string]string{
		"access_token":  t,
		"refresh_token": rt,
	}, nil
}

func getTokenPair(w http.ResponseWriter, r *http.Request) {
	params := r.URL.Query().Get("user_id")
	userID, err := primitive.ObjectIDFromHex(params)
	if err != nil {
		UnprocessableEntity(w, err)
		return
	}

	tokens, err := generateTokenPair(userID)
	if err != nil {
		InternalServerError(w, err)
		return
	}

	tokens["refresh_token"] = base64.StdEncoding.EncodeToString([]byte(tokens["refresh_token"]))

	Ok(w, map[string]interface{}{
		"access_token": tokens["access_token"],
		"refresh_token": tokens["refresh_token"],
	})
}

func refreshTokenPair(w http.ResponseWriter, r *http.Request) {
	type tokenRequestBody struct {
		RefreshToken string `json:"refresh_token"`
	}

	tokenReq := tokenRequestBody{}

	err := json.NewDecoder(r.Body).Decode(&tokenReq)
	if err != nil {
		InternalServerError(w, err)
		return
	}

	if r.Body == nil {
		BadRequest(w, err)
	}

	token, err := base64.StdEncoding.DecodeString(tokenReq.RefreshToken)
	if err != nil {
		InternalServerError(w, err)
		return
	}

	refreshToken, err := jwt.Parse(string(token), func(refreshToken *jwt.Token) (interface{}, error) {
		if _, ok := refreshToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, err
		}

		return []byte("refresh_secret"), nil
	})
	if err != nil {
		BadRequest(w, err)
		return
	}

	refreshClaims := refreshToken.Claims.(jwt.MapClaims)
	userID, err := primitive.ObjectIDFromHex(refreshClaims["user_id"].(string))

	if refreshClaims, ok := refreshToken.Claims.(jwt.MapClaims); ok && refreshToken.Valid {

		filter := bson.M{"access_token_uuid": refreshClaims["access_token_uuid"]}
		collection := helper.ConnectionDB()

		var baseToken models.Token
		err = collection.FindOne(context.TODO(), filter).Decode(&baseToken)
		if err != nil {
			InternalServerError(w, err)
			return
		}

		if !CheckHashRefreshToken(string(token), baseToken.Data) {
			BadRequest(w, err)
			return
		}

		removingResult, err := collection.DeleteOne(context.TODO(), filter)
		if err != nil {
			InternalServerError(w, err)
			return
		}
		log.Println(removingResult)

		tokens, err := generateTokenPair(userID)
		if err != nil {
			InternalServerError(w, err)
			return
		}

		tokens["refresh_token"] = base64.StdEncoding.EncodeToString([]byte(tokens["refresh_token"]))

		Ok(w, map[string]interface{}{
			"access_token": tokens["access_token"],
			"refresh_token": tokens["refresh_token"],
		})
	} else {
		BadRequest(w, err)
		return
	}
}

func deleteSpecificToken(w http.ResponseWriter, r *http.Request) {
	args := mux.Vars(r)
	tokenID, err := primitive.ObjectIDFromHex(args["token_id"])
	if err != nil {
		UnprocessableEntity(w, err)
		return
	}

	filter := bson.M{"_id": tokenID}

	collection := helper.ConnectionDB()
	result, err := collection.DeleteOne(context.TODO(), filter)
	if err != nil {
		InternalServerError(w, err)
		return
	}

	Ok(w, result)
}

func deleteAllTokensForUser(w http.ResponseWriter, r *http.Request) {
	var token models.Token
	err := json.NewDecoder(r.Body).Decode(&token)
	if err != nil {
		UnprocessableEntity(w, err)
		return
	}

	filter := bson.M{"user_id": token.UserID}

	collection := helper.ConnectionDB()
	result, err := collection.DeleteMany(context.TODO(), filter)
	if err != nil {
		InternalServerError(w, err)
		return
	}

	Ok(w, result)
}

func main() {

	router := mux.NewRouter()

	router.HandleFunc("/tokens", getTokenPair).Methods(http.MethodPost)
	router.HandleFunc("/tokens/refresh", refreshTokenPair).Methods(http.MethodPost)
	router.HandleFunc("/tokens/{token_id}", deleteSpecificToken).Methods(http.MethodDelete)
	router.HandleFunc("/tokens", deleteAllTokensForUser).Methods(http.MethodDelete)

	server := http.Server{
		Addr:    addr,
		Handler: router,
	}

	log.Println("Listening on address:", addr)

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
