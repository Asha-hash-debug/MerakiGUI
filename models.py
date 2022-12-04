from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()


class UserModel(db.Model):
    __tablename__ = "Users"
    id = db.Column(db.Integer, primary_key=True)
    UserName = db.Column(db.String(20), unique=True, nullable=False)
    Role = db.Column(db.String(10),nullable=False)
    Email = db.Column(db.String(120), unique=True, nullable=False)
    Password = db.Column(db.String(20),nullable=False)
    Contact = db.Column(db.String(20),nullable=False)
    imageURL =db.Column(db.String(20),nullable=False)

    def __init__(self,UserName,Role,Email,Password,Contact,imageURL):
        self.UserName = UserName
        self.Role = Role
        self.Email = Email
        self.Password = Password
        self.Contact = Contact
        self.imageURL = imageURL

    def json(self):
        return {'id':self.id,'UserName':self.UserName,'Role':self.Role,'Email':self.Email,'Password':self.Password,'Contact':self.Contact,'imageURL':self.imageURL}

    def __repr__(self):
        return f"User('{self.UserName}', '{self.Email}')"