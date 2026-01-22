# local import
from src.age_oauth.oauth import get_gis

# construct the gis object
x = get_gis()

# simple whoami
print(x.users.me)
