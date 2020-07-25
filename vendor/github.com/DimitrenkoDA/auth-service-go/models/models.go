package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Token struct {
	ID     primitive.ObjectID `json:"_id,omitempty" bson:"_id,omitempty"`
	UserID primitive.ObjectID `json:"user_id,omitempty" bson:"user_id,omitempty"`
	AccessTokenUUID string `json:"access_token_uuid,omitempty" bson:"access_token_uuid,omitempty"`
	Data   string             `json:"data,omitempty" bson:"data,omitempty"`
}
