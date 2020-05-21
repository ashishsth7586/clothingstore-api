from models.user import UserModel
from marshmallow_sqlalchemy import ModelSchema


class UserRegisterSchema(ModelSchema):
    class Meta:
        model = UserModel
        load_only = ('password', 'created_at')   # returning password is vulnerable
        dump_only = ('id',)         # ID is automatically added to each user.


class UserLoginSchema(ModelSchema):
    class Meta:
        model = UserModel
        fields = ("username", "password")
        load_only = ("password", )
