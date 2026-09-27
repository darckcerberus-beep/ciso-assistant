"""User, team, and actor identity models and management.

Handles API operations for:
- User accounts (authentication & email lookups).
- Teams/IAM groups.
- Actors (representatives/owners assignable to audits and controls).
"""

import logging
from .. import utils

LOGGER = logging.getLogger(__name__)


class User:
    """Represents a single system user."""

    def __init__(self, json_user):
        self.json_object = json_user

    def get_json(self):
        return self.json_object

    def get_full_name(self):
        return (self.json_object.get('first_name', '') + ' ' + self.json_object.get('last_name', '')).strip()

    def get_email(self):
        return self.json_object.get('email', '')

    def get_id(self):
        return self.json_object.get('id', '')

    def is_superuser(self) -> bool:
        """Check if user is a superuser."""
        return bool(self.json_object.get('is_superuser', False))

    def is_third_party(self) -> bool:
        """Check if user is marked as a third-party account."""
        return bool(self.json_object.get('is_third_party', False))

    def is_admin(self) -> bool:
        """Check if user has administrative privileges (superuser or administrator group)."""
        if self.is_superuser():
            return True
        user_groups = self.json_object.get('user_groups', [])
        for group in user_groups:
            name = group.get('str', '') if isinstance(group, dict) else str(group)
            if 'admin' in name.lower():
                return True
        return False


class UserDict:
    """Handles collections of users and lookup by name/email."""

    def __init__(self):
        self.reload()

    def reload(self):
        """Reload all users from the API."""
        self.users = [User(u) for u in utils.get_all_results("/api/users/", force_reload=True)]

    def get_users(self):
        return self.users
    def print_users(self):
        print("Users:")
        for u in self.users:
            print(f"Full Name: {u.get_full_name()}")
            print(f"Email: {u.get_email()}")
            print(f"ID: {u.get_id()}")
    def get_id_from_name(self, name):
        for u in self.users:
            if u.get_full_name() == name:
                return u.get_id()
        return None
    def get_id_from_email(self, email):
        for u in self.users:
            if u.get_email() == email:
                return u.get_id()
        return None    
    def get_name_from_id(self, id):
        for u in self.users:
            if u.get_id() == id:
                return u.get_full_name()
        return None
    def get_name_from_email(self, email):
        for u in self.users:
            if u.get_email() == email:
                return u.get_full_name()
        return None
    def upsert_user(self, first_name, last_name, email,group):
        # Check if the user already exists
        for u in self.users:
            if u.get_email() == email:
                print(f"User '{email}' already exists.")
                return u
        # Check if the team exists
        team_dict = TeamDict()
        team_id = team_dict.get_id_from_name(group)
        if team_id is None:
            print(f"Team '{group}' does not exist. Creating it.")
            team_dict.upsert_team(group)
            team_id = team_dict.get_id_from_name(group)

        # If the user does not exist, create it
        payload = {'first_name': first_name, 'last_name': last_name, 'email': email, 'team': team_id}
        result = utils.get_return("/api/users/", method="POST", payload=payload)
        print(f"Result: {result}")
        if result and (not isinstance(result, dict) or not result.get("error")):
            print(f"User '{email}' created successfully.")
            self.reload()
            return result
        else:
            print(f"Failed to create user '{email}': {result}")
            return None

    def get_user_by_id(self, user_id):
        """Retrieve User instance by UUID."""
        for u in self.users:
            if u.get_id() == user_id:
                return u
        return None

    def get_user_by_email(self, email):
        """Retrieve User instance by email address."""
        norm_email = (email or "").strip().lower()
        for u in self.users:
            if u.get_email().strip().lower() == norm_email:
                return u
        return None

    def is_protected_user(self, user_id=None, email=None) -> bool:
        """Check if a user is an administrator, superuser, or internal (non-third-party) account that must be protected."""
        user = None
        if user_id:
            user = self.get_user_by_id(user_id)
        elif email:
            user = self.get_user_by_email(email)
        if not user:
            return False
        return user.is_superuser() or user.is_admin() or not user.is_third_party()

    def delete_user(self, email, allow_admin=False):
        # Check if the user exists
        norm_email = (email or "").strip().lower()
        for u in self.users:
            if u.get_email().strip().lower() == norm_email:
                if not allow_admin and self.is_protected_user(email=norm_email) is True:
                    LOGGER.warning(
                        "Refusing to delete protected user '%s' (ID: %s).",
                        u.get_email(),
                        u.get_id(),
                    )
                    return False
                user_id = u.get_id()
                result = utils.get_return(f"/api/users/{user_id}/", method="DELETE")
                if result is True or (isinstance(result, dict) and not result.get("error")):
                    LOGGER.info("User '%s' deleted successfully.", email)
                    self.reload()
                    return True
                else:
                    LOGGER.warning("Failed to delete user '%s': %s", email, result)
                    return False
        LOGGER.warning("User '%s' does not exist.", email)
        return False

    def upsert_user_from_user_dict(self, user_dict):
        first_name = user_dict.get('first_name', '')
        last_name = user_dict.get('last_name', '')
        email = user_dict.get('email', '')
        group = user_dict.get('group', '')
        return self.upsert_user(first_name, last_name, email, group)

    def create_user_if_missing(self, email, first_name="", last_name="", is_third_party=True):
        """Create a user account if one with the specified email does not exist."""
        norm_email = (email or "").strip().lower()
        for u in self.users:
            if u.get_email().strip().lower() == norm_email:
                return u.get_json()

        payload = {
            "email": norm_email,
            "first_name": first_name or "",
            "last_name": last_name or "",
            "is_third_party": is_third_party,
            "is_active": True,
        }
        res = utils.get_return("/api/users/", method="POST", payload=payload)
        if res and (not isinstance(res, dict) or not res.get("error")):
            self.reload()
            return res
        return None

    def delete_user_by_id(self, user_id, allow_admin=False):
        """Delete user account by ID.
        
        Refuses to delete protected users (administrators, superusers, internal users) unless allow_admin is True.
        """
        if not allow_admin and self.is_protected_user(user_id=user_id) is True:
            user = self.get_user_by_id(user_id)
            user_label = user.get_email() if user else user_id
            LOGGER.warning(
                "Refusing to delete protected user '%s' (ID: %s).",
                user_label,
                user_id,
            )
            return False

        res = utils.get_return(f"/api/users/{user_id}/", method="DELETE")
        if res is True or (isinstance(res, dict) and not res.get("error")):
            self.reload()
            return True
        return False


class Team:
    def __init__(self, json_user_group):
        self.json_object = json_user_group
    def get_name(self):
        return self.json_object.get('name', '')
    def get_id(self):
        return self.json_object.get('id', '')
    def get_member_names(self):
        return [member.get('str', '') for member in self.json_object.get('members', [])]
    def get_member_ids(self):
        return [member.get('id', '') for member in self.json_object.get('members', [])]
    def add_user(self, user_id):
        current_users = self.get_member_ids()  # Refresh the member list
        print(f"Current members of team '{self.get_name()}': {current_users}")
        # check if the user is already a member of the team
        if user_id in current_users:
            print(f"User with ID '{user_id}' is already a member of team '{self.get_name()}'.")
            return False
        else:
            current_users.append(user_id)  # Add the new user to the list
            payload = {'members': current_users}    
            result = utils.get_return(f"/api/teams/{self.get_id()}/", method="PATCH", payload=payload)
            print(f"Result: {result}")
            if result and (not isinstance(result, dict) or not result.get("error")):
                print(f"User with ID '{user_id}' added to team '{self.get_name()}' successfully.")
                return True
            else:
                print(f"Failed to add user with ID '{user_id}' to team '{self.get_name()}': {result}")
                return False        
    def remove_user(self, user_id):
        current_users = self.get_member_ids()  # Refresh the member list
        print(f"Current members of team '{self.get_name()}': {current_users}")
        # check if the user is a member of the team
        if user_id in current_users:
            current_users.remove(user_id)  # Remove the user from the list
            payload = {'members': current_users}    
            result = utils.get_return(f"/api/teams/{self.get_id()}/", method="PATCH", payload=payload)
            print(f"Result: {result}")
            if result and (not isinstance(result, dict) or not result.get("error")):
                print(f"User with ID '{user_id}' removed from team '{self.get_name()}' successfully.")
                return True
            else:
                print(f"Failed to remove user with ID '{user_id}' from team '{self.get_name()}': {result}")
                return False        
        else:
            print(f"User with ID '{user_id}' is not a member of team '{self.get_name()}'.")
            return False


class TeamDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.teams = [Team(t) for t in utils.get_all_results("/api/teams/", force_reload=True)]

    def get_teams(self):
        return self.teams
    def print_teams(self):
        print("Teams:")
        for t in self.teams:
            print(f"Name: {t.get_name()}")
            print(f"ID: {t.get_id()}")
            print(f"MEMBER NAMES: {t.get_member_names()}")
            print(f"MEMBER IDs: {t.get_member_ids()}")
    def get_id_from_name(self, name):
        for t in self.teams:
            if t.get_name() == name:
                return t.get_id()
        return None
    def get_name_from_id(self, id):
        for t in self.teams:
            if t.get_id() == id:
                return t.get_name()
        return None
    def upsert_team(self, name):
        # Check if the team already exists
        for t in self.teams:
            if t.get_name() == name:
                print(f"Team '{name}' already exists.")
                return t
        # If the team does not exist, create it
        payload = {'name': name}
        result = utils.get_return("/api/teams/", method="POST", payload=payload)
        print(f"Result: {result}")
        if result and (not isinstance(result, dict) or not result.get("error")):
            print(f"Team '{name}' created successfully.")
            self.reload()
            return result
        else:
            print(f"Failed to create team '{name}': {result}")
            return None
    def add_user_to_team(self, team_name, user_email):
        team_id = self.get_id_from_name(team_name)
        if team_id is None:
            print(f"Team '{team_name}' does not exist.")
            return False
        user_dict = UserDict()
        user_id = user_dict.get_id_from_email(user_email)
        if user_id is None:
            print(f"User '{user_email}' does not exist.")
            return False
        team = Team(utils.get_return(f"/api/teams/{team_id}"))
        return team.add_user(user_id)
    def remove_user_from_team(self, team_name, user_email):
        team_id = self.get_id_from_name(team_name)
        if team_id is None:
            print(f"Team '{team_name}' does not exist.")
            return False
        user_dict = UserDict()
        user_id = user_dict.get_id_from_email(user_email)
        if user_id is None:
            print(f"User '{user_email}' does not exist.")
            return False
        team = Team(utils.get_return(f"/api/teams/{team_id}"))
        return team.remove_user(user_id)   

class Actor:
    def __init__(self, json_actor):
        self.json_object = json_actor
    def get_name(self):
        return self.json_object.get('str', '')
    def get_id(self):
        return self.json_object.get('id', '')

class ActorDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.actors = [Actor(a) for a in utils.get_all_results("/api/actors/", force_reload=True)]

    def get_actors(self):
        return self.actors
    def print_actors(self):
        print("Actors:")
        for a in self.actors:
            print(f"Name: {a.get_name()}")
            print(f"ID: {a.get_id()}")
    def get_id_from_name(self, name):
        print(f"Searching for actor with name '{name}'")
        for a in self.actors:
            if a.get_name() == name:
                return a.get_id()
        return None
    def get_name_from_id(self, id):
        for a in self.actors:
            if a.get_id() == id:
                return a.get_name()
        return None