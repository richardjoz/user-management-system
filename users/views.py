from django.shortcuts import render
import environ
import jwt
from datetime import datetime, timedelta
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from users.authentication.jwt_tokens import UserTokenAuthentication
from users.authentication.permissions import IsUserAuthenticated
from sqlalchemy.exc import SQLAlchemyError
from User_Management.dbsession import Session
from users.models import UserLogin, UserToken, UserProfile, Notes
from users.utils import verify_password, hash_password
import os
from django.views.generic import TemplateView

env = environ.Env()
environ.Env.read_env()

class FrontendView(TemplateView):
    template_name = "frontend/index.html"


class UserLoginAPIView(APIView):
    """User Login API View"""

    permission_classes = [AllowAny]

    def post(self, request):
        session = Session()
        try:
            username = request.data['username']
            password = request.data['password']
            current_datetime = datetime.now().replace(microsecond=0)

            if not username or not password:
                return Response({"error": "Username and password are required"}, status=status.HTTP_400_BAD_REQUEST)

            user = session.query(UserLogin).filter_by(username=username).first()
            if not user or not verify_password(password, user.password_hash):
                return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

            # Load appropriate profile based on user type
            profile = session.query(UserProfile).filter_by(id=user.profile_id).one_or_none()

            if not profile:
                return Response({"error": "Profile not found"}, status=status.HTTP_404_NOT_FOUND)

            if profile.status != "active":
                return Response({"error": "User not active"}, status=status.HTTP_403_FORBIDDEN)

            # Create token
            user_token = UserToken()
            iat = datetime.now()
            exp = iat + timedelta(days=1)
            user_token.auth_id = user.id
            user_token.iat = iat
            user_token.exp = exp
            payload = {
                'auth_id': user.id,
                'iat': int(iat.timestamp()),
                'exp': int(exp.timestamp())
                }
            token = jwt.encode(payload, env('SECRET_KEY'), algorithm='HS256')
            user_token.token = token

            # Update login info
            session.query(UserProfile).filter(UserProfile.id == user.profile_id).update({'last_login': current_datetime})
            session.query(UserToken).filter(UserToken.auth_id == user.id).delete()
            session.add(user_token)
            session.commit()

            # Prepare user data
            user_data = {
                "token": token,
                "username": user.username,
                "name": profile.name,
                "email": profile.email,
                "contact_no": profile.contact_no,
                "status": profile.status,
                "token_expiry": user_token.exp,
                }
            return Response({
                "response": "success",
                "message": "User logged in successfully",
                "data": user_data
                }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                'response': 'error', 'message': 'Database error', 'errors': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                'response': 'error', 'message': 'Something went wrong, please try again', 'errors': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class UserLogoutAPIView(APIView):
    """User Logout API View"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def post(self, request):
        session = Session()
        try:
            token = request.auth
            user = request.user
            print("User:", request.user)
            print("Auth:", request.auth)

            session.query(UserToken).filter_by(token=token, auth_id=user.id).delete()
            session.commit()
            return Response({
                "response": "success",
                "message": "User logged out successfully"
                }, status=status.HTTP_200_OK)
        
        except SQLAlchemyError as e:
            print(e)
            session.rollback()
            return Response({
                'response': 'error', 
                'message': 'Database error', 
                'errors': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except Exception as e:
            print(e)
            session.rollback()
            return Response({
                'response': 'error', 
                'message': 'Something went wrong, please try again', 
                'errors': str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        finally:
            session.close()


class UserRegisterAPIView(APIView):
    """User Registration API View"""
    permission_classes = [AllowAny]

    def post(self, request):
        session = Session()
        try:
            data = request.data
            name = data.get('name')
            email = data.get('email')
            username = data.get('username')
            password = data.get('password')
            contact_no = data.get('contact_no')
            gender = data.get('gender')
            address = data.get('address')

            # Parse date (frontend sends YYYY-MM-DD)
            dob_str = data.get('dob')
            dob = None
            if dob_str:
                try:
                    dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
                except ValueError:
                    return Response({'error': 'Invalid date format, expected YYYY-MM-DD'}, status=400)

            # Basic validation
            if not all([name, email, username, password]):
                return Response({
                    "response": "error",
                    "message": "Name, email, username, and password are required"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if email/username already exists
            if session.query(UserProfile).filter_by(email=email).first():
                return Response({
                    "response": "error",
                    "message": "Email already registered"
                }, status=status.HTTP_400_BAD_REQUEST)

            if session.query(UserLogin).filter_by(username=username).first():
                return Response({
                    "response": "error",
                    "message": "Username already exists"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create Profile
            profile = UserProfile(
                name=name,
                gender=gender or None,
                dob=dob,
                contact_no=contact_no or None,
                email=email,
                address=address or None,
                status="active",
                created_at=datetime.now(),
                last_login=datetime.now()
            )
            session.add(profile)
            session.flush()  # To get profile.id before committing

            # Create Auth record
            user_auth = UserLogin(
                profile_id=profile.id,
                username=username,
                password_hash=hash_password(password),
                created_at=datetime.now()
            )
            session.add(user_auth)
            session.commit()

            return Response({
                "response": "success",
                "message": "User registered successfully",
                "data": {
                    "username": username,
                    "email": email,
                    "name": name,
                    "contact_no": contact_no,
                    "status": "active"
                }
            }, status=status.HTTP_201_CREATED)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Database error",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class ChangePasswordAPIView(APIView):
    """Change Password API View"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def put(self, request):
        session = Session()
        try:
            user = request.user
            login = session.query(UserLogin).filter_by(id=user.id).first()

            if not login:
                return Response({
                    'response': 'error',
                    'message': 'User not found.'
                }, status=status.HTTP_404_NOT_FOUND)

            old_password = request.data.get('old_password')
            new_password = request.data.get('new_password')

            # Basic validation
            if not old_password or not new_password:
                return Response({
                    'response': 'error',
                    'message': 'Both old and new passwords are required.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Verify old password
            if not verify_password(old_password, user.password_hash):
                return Response({
                    'response': 'error',
                    'message': 'Old password is incorrect.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prevent reusing same password
            if verify_password(new_password, user.password_hash):
                return Response({
                    'response': 'error',
                    'message': 'New password cannot be the same as the old password.'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Update password
            login.password_hash = hash_password(new_password)
            session.add(login)
            session.commit()
            return Response({
                'response': 'success',
                'message': 'Password changed successfully.'
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                'response': 'error',
                'message': 'Database error.',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                'response': 'error',
                'message': 'Something went wrong.',
                'errors': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class UserProfileViewAPIView(APIView):
    """View User Profile API View"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def get(self, request):
        session = Session()
        try:
            user = request.user

            # Fetch user profile
            profile = (
                session.query(UserProfile)
                .filter_by(id=user.profile_id)
                .one_or_none()
            )

            if not profile:
                return Response(
                    {"error": "Profile not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            profile_data = {
                "name": profile.name,
                "email": profile.email,
                "gender": profile.gender,
                "dob": profile.dob,
                "contact_no": profile.contact_no,
                "address": profile.address,
                "status": profile.status,
                "last_login": profile.last_login,
                "created_at": profile.created_at,
            }

            return Response({
                "response": "success",
                "message": "Profile retrieved successfully",
                "data": profile_data,
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Database error",
                "errors": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Unexpected error occurred",
                "errors": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class UserProfileUpdateAPIView(APIView):
    """Update User Profile API View"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def put(self, request):
        session = Session()
        try:
            user = request.user
            data = request.data

            profile = (
                session.query(UserProfile)
                .filter_by(id=user.profile_id)
                .one_or_none()
            )

            if not profile:
                return Response(
                    {"error": "Profile not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Update allowed fields
            allowed_fields = ['name', 'gender', 'dob', 'contact_no', 'email', 'address']
            for field in allowed_fields:
                if field in data and data[field] is not None:
                    setattr(profile, field, data[field])

            session.commit()

            return Response({
                "response": "success",
                "message": "Profile updated successfully",
                "data": {
                    "name": profile.name,
                    "email": profile.email,
                    "gender": profile.gender,
                    "dob": profile.dob,
                    "contact_no": profile.contact_no,
                    "address": profile.address,
                    "status": profile.status,
                },
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Database error",
                "errors": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Unexpected error occurred",
                "errors": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class CreateNoteAPIView(APIView):
    """Create a new note for the authenticated user"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def post(self, request):
        session = Session()
        try:
            user = request.user
            data = request.data

            title = data.get('title')
            description = data.get('description')
            attachment_file = request.FILES.get('attachment')

            if not title:
                return Response({"error": "Title is required"}, status=status.HTTP_400_BAD_REQUEST)

            attachment_path = None
            if attachment_file:
                upload_dir = 'media/notes/'
                os.makedirs(upload_dir, exist_ok=True)
                attachment_path = os.path.join(upload_dir, attachment_file.name)

                with open(attachment_path, 'wb+') as dest:
                    for chunk in attachment_file.chunks():
                        dest.write(chunk)

            note = Notes(
                auth_id=user.id,
                title=title,
                description=description,
                attachment=attachment_path,
                created_at=datetime.now(),
                modified_at=datetime.now()
            )

            session.add(note)
            session.commit()

            return Response({
                "response": "success",
                "message": "Note created successfully",
                "data": {
                    "id": note.id,
                    "title": note.title,
                    "description": note.description,
                    "attachment": note.attachment,
                    "created_at": note.created_at
                }
            }, status=status.HTTP_201_CREATED)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Database error",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error",
                "message": "Unexpected error occurred",
                "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class ListNotesAPIView(APIView):
    """List all notes of the authenticated user"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def get(self, request):
        session = Session()
        try:
            user = request.user

            notes = session.query(Notes).filter_by(auth_id=user.id).order_by(Notes.created_at.desc()).all()

            data = [{
                "id": n.id,
                "title": n.title,
                "description": n.description,
                "attachment": n.attachment,
                "created_at": n.created_at,
                "modified_at": n.modified_at
            } for n in notes]

            return Response({
                "response": "success",
                "message": "Notes fetched successfully",
                "count": len(data),
                "data": data
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error", "message": "Database error", "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error", "message": "Unexpected error", "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class UpdateNoteAPIView(APIView):
    """Update an existing note"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def put(self, request, note_id):
        session = Session()
        try:
            user = request.user
            data = request.data

            note = session.query(Notes).filter_by(id=note_id, auth_id=user.id).one_or_none()
            if not note:
                return Response({"error": "Note not found"}, status=status.HTTP_404_NOT_FOUND)

            # Update allowed fields
            if 'title' in data:
                note.title = data['title']
            if 'description' in data:
                note.description = data['description']
            if 'attachment' in request.FILES:
                attachment_file = request.FILES['attachment']
                upload_dir = 'media/notes/'
                os.makedirs(upload_dir, exist_ok=True)
                attachment_path = os.path.join(upload_dir, attachment_file.name)

                with open(attachment_path, 'wb+') as dest:
                    for chunk in attachment_file.chunks():
                        dest.write(chunk)
                note.attachment = attachment_path

            note.modified_at = datetime.now()
            session.commit()

            return Response({
                "response": "success",
                "message": "Note updated successfully",
                "data": {
                    "id": note.id,
                    "title": note.title,
                    "description": note.description,
                    "attachment": note.attachment,
                    "modified_at": note.modified_at
                }
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error", "message": "Database error", "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error", "message": "Unexpected error", "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()


class DeleteNoteAPIView(APIView):
    """Delete a specific note"""

    authentication_classes = [UserTokenAuthentication]
    permission_classes = [IsUserAuthenticated]

    def delete(self, request, note_id):
        session = Session()
        try:
            user = request.user

            note = session.query(Notes).filter_by(id=note_id, auth_id=user.id).one_or_none()
            if not note:
                return Response({"error": "Note not found"}, status=status.HTTP_404_NOT_FOUND)

            session.delete(note)
            session.commit()

            return Response({
                "response": "success",
                "message": "Note deleted successfully"
            }, status=status.HTTP_200_OK)

        except SQLAlchemyError as e:
            session.rollback()
            return Response({
                "response": "error", "message": "Database error", "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            session.rollback()
            return Response({
                "response": "error", "message": "Unexpected error", "errors": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        finally:
            session.close()
