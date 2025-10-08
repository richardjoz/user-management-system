from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session,sessionmaker
from django.conf import settings


def Session():
    engine = create_engine(settings.DATABASE_ENGINE)
    _Session = scoped_session(sessionmaker(bind=engine, expire_on_commit=False))
    return _Session()
