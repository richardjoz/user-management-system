from django.db import models
from sqlalchemy import Column, Integer, String, ForeignKey, Enum, DateTime, Boolean, Text
from sqlalchemy.orm import declarative_base, relationship
from django.utils.timezone import now

# Create your models here.

Base = declarative_base()
metadata = Base.metadata


class UserTokenTbl(models.Model):
    """User Token Model"""
    auth = models.ForeignKey('UserLoginTbl', on_delete=models.CASCADE, related_name='tokens')
    token = models.CharField(max_length=191, unique=True)
    iat = models.DateTimeField(default=now)
    exp = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'um_user_tokens'

    def __str__(self):
        return f"Token for {self.auth} - {self.token}"


class UserToken(Base):
    """SQLAlchemy User Token Model"""
    __tablename__ = 'um_user_tokens'

    id = Column(Integer, primary_key=True)
    auth_id = Column(Integer, ForeignKey('um_user_auths.id', ondelete="CASCADE"), nullable=False)
    token = Column(String(191), unique=True, nullable=False)
    iat = Column(DateTime, default=now)
    exp = Column(DateTime, nullable=True)

    # Relationships
    auth = relationship("UserLogin", back_populates="tokens")


class UserLoginTbl(models.Model):
    """User Authentication Model"""
    profile = models.OneToOneField("UserProfileTbl", on_delete=models.CASCADE, related_name="auth")
    username = models.CharField(max_length=191, unique=True, null=False)
    password_hash = models.CharField(max_length=191, null=False)
    created_at = models.DateTimeField(default=now)

    class Meta:
        db_table = 'um_user_auths'

    def __str__(self):
        return f"{self.username}"


class UserLogin(Base):
    """SQLAlchemy User Authentication Model"""
    __tablename__ = "um_user_auths"

    id = Column(Integer, primary_key=True, autoincrement=True)
    profile_id = Column(Integer, ForeignKey("um_user_profiles.id", ondelete="CASCADE"), unique=True, nullable=False)
    username = Column(String(191), unique=True, nullable=False)
    password_hash = Column(String(191), nullable=False)
    created_at = Column(DateTime, default=now)

    # Relationships
    tokens = relationship("UserToken", back_populates="auth", cascade="all, delete-orphan")
    profile = relationship("UserProfile", uselist=False, back_populates="auth")
    notes = relationship("Notes", back_populates="auth", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(username={self.username})>"


class UserProfileTbl(models.Model):
    """User Profile Model"""
    name = models.CharField(max_length=191)
    gender = models.CharField(max_length=10, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    contact_no = models.CharField(max_length=20, null=True, blank=True)
    email = models.EmailField(max_length=191, unique=True)
    address = models.TextField(null=True, blank=True)
    status = models.CharField(max_length=191,null=True)
    last_login = models.DateTimeField(auto_now_add=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'um_user_profiles'

    def __str__(self):
        return f"{self.name} ({self.role})"


class UserProfile(Base):
    """SQLAlchemy User Profile Model"""
    __tablename__ = "um_user_profiles"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(191), nullable=False)
    gender = Column(String(10), nullable=True)
    dob = Column(DateTime, nullable=True)
    contact_no = Column(String(20), nullable=True)
    email = Column(String(191), unique=True, nullable=False)
    address = Column(String(500), nullable=True)
    status = Column(String(220), nullable=True)
    last_login = Column(DateTime, default=now)
    created_at = Column(DateTime, default=now)
    
    # Relationships
    auth = relationship("UserLogin", uselist=False, back_populates="profile")

    def __repr__(self):
        return f"<UserProfile(name={self.name}, role={self.role})>"


class NotesTbl(models.Model):
    """Notes ORM Model"""
    auth = models.ForeignKey(
        'UserLoginTbl', 
        on_delete=models.CASCADE, 
        related_name='notes'
    )
    title = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    attachment = models.FileField(upload_to='notes/', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    modified_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'um_user_notes'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.title} (by {self.auth.username})"


class Notes(Base):
    """SQLAlchemy Notes Model"""
    __tablename__ = "um_user_notes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    auth_id = Column(Integer, ForeignKey("um_user_auths.id", ondelete="CASCADE"), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    attachment = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=now)
    modified_at = Column(DateTime, default=now, onupdate=now)

    # Relationships
    auth = relationship("UserLogin", back_populates="notes")

    def __repr__(self):
        return f"<Note(title={self.title}, user={self.auth.username})>"
