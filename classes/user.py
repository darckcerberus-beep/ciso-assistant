import logging
from . import utils

class User:
    def __init__(self, json_user):
        self.json_object = json_user
    def getJSON(self):
        return self.json_object    
    def getFullName(self):
        return self.json_object.get('first_name', '') + ' ' + self.json_object.get('last_name', '')
    def getEmail(self):
        return self.json_object.get('email', '')    
    def getID(self):
        return self.json_object.get('id', '')

class UserDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.users = [User(u) for u in utils.get_all_results("/api/users/")]

    def getUsers(self):
        return self.users
    def printUsers(self):
        print("Users:")
        for u in self.users:
            print(f"Full Name: {u.getFullName()}")
            print(f"Email: {u.getEmail()}")
            print(f"ID: {u.getID()}")
    def getIDfromName(self, name):
        for u in self.users:
            if u.getFullName() == name:
                return u.getID()
        return None
    def getIDfromEmail(self, email):
        for u in self.users:
            if u.getEmail() == email:
                return u.getID()
        return None    
    def getNamefromID(self, id):
        for u in self.users:
            if u.getID() == id:
                return u.getFullName()
        return None
    def getNamefromEmail(self, email):
        for u in self.users:
            if u.getEmail() == email:
                return u.getFullName()
        return None
    def upsertUser(self, first_name, last_name, email,group):
        # Check if the user already exists
        for u in self.users:
            if u.getEmail() == email:
                print(f"User '{email}' already exists.")
                return u
        # Check if the team exists
        team_dict = TeamDict()
        team_id = team_dict.getIDfromName(group)
        if team_id is None:
            print(f"Team '{group}' does not exist. Creating it.")
            team_dict.upsertTeam(group)
            team_id = team_dict.getIDfromName(group)

        # If the user does not exist, create it
        payload = {'first_name': first_name, 'last_name': last_name, 'email': email, 'team': team_id}
        result = utils.get_return("/api/users/", method="POST", payload=payload)
        print(f"Result: {result}")
        if result and not isinstance(result, dict) or not result.get("error"):
            print(f"User '{email}' created successfully.")
            self.reload()
            return result
        else:
            print(f"Failed to create user '{email}': {result}")
            return None

    def deleteUser(self, email):
        # Check if the user exists
        for u in self.users:
            if u.getEmail() == email:
                user_id = u.getID()
                result = utils.get_return(f"/api/users/{user_id}/", method="DELETE")
                print(f"Result: {result}")
                if result and not isinstance(result, dict) or not result.get("error"):
                    print(f"User '{email}' deleted successfully.")
                    self.reload()
                    return True
                else:
                    print(f"Failed to delete user '{email}': {result}")
                    return False
        print(f"User '{email}' does not exist.")
        return False

    def upsertUserFromUserDict(self, user_dict):
        first_name = user_dict.get('first_name', '')
        last_name = user_dict.get('last_name', '')
        email = user_dict.get('email', '')
        group = user_dict.get('group', '')
        return self.upsertUser(first_name, last_name, email, group)


class Team:
    def __init__(self, json_user_group):
        self.json_object = json_user_group
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def getMemberNames(self):
        return [member.get('str', '') for member in self.json_object.get('members', [])]
    def getMemberIDs(self):
        return [member.get('id', '') for member in self.json_object.get('members', [])]
    def AddUser(self, user_id):
        CurrentUsers = self.getMemberIDs()  # Refresh the member list
        print(f"Current members of team '{self.getName()}': {CurrentUsers}")
        # check if the user is already a member of the team
        if user_id in CurrentUsers:
            print(f"User with ID '{user_id}' is already a member of team '{self.getName()}'.")
            return False
        else:
            CurrentUsers.append(user_id)  # Add the new user to the list
            payload = {'members': CurrentUsers}    
            result = utils.get_return(f"/api/teams/{self.getID()}/", method="PATCH", payload=payload)
            print(f"Result: {result}")
            if result and not isinstance(result, dict) or not result.get("error"):
                print(f"User with ID '{user_id}' added to team '{self.getName()}' successfully.")
                return True
            else:
                print(f"Failed to add user with ID '{user_id}' to team '{self.getName()}': {result}")
                return False        
    def RemoveUser(self, user_id):
        CurrentUsers = self.getMemberIDs()  # Refresh the member list
        print(f"Current members of team '{self.getName()}': {CurrentUsers}")
        # check if the user is a member of the team
        if user_id in CurrentUsers:
            CurrentUsers.remove(user_id)  # Remove the user from the list
            payload = {'members': CurrentUsers}    
            result = utils.get_return(f"/api/teams/{self.getID()}/", method="PATCH", payload=payload)
            print(f"Result: {result}")
            if result and not isinstance(result, dict) or not result.get("error"):
                print(f"User with ID '{user_id}' removed from team '{self.getName()}' successfully.")
                return True
            else:
                print(f"Failed to remove user with ID '{user_id}' from team '{self.getName()}': {result}")
                return False        
        else:
            print(f"User with ID '{user_id}' is not a member of team '{self.getName()}'.")
            return False


class TeamDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.teams = [Team(t) for t in utils.get_all_results("/api/teams/")]

    def getTeams(self):
        return self.teams
    def printTeams(self):
        print("Teams:")
        for t in self.teams:
            print(f"Name: {t.getName()}")
            print(f"ID: {t.getID()}")
            print(f"MEMBER NAMES: {t.getMemberNames()}")
            print(f"MEMBER IDs: {t.getMemberIDs()}")
    def getIDfromName(self, name):
        for t in self.teams:
            if t.getName() == name:
                return t.getID()
        return None
    def getNamefromID(self, id):
        for t in self.teams:
            if t.getID() == id:
                return t.getName()
        return None
    def upsertTeam(self, name):
        # Check if the team already exists
        for t in self.teams:
            if t.getName() == name:
                print(f"Team '{name}' already exists.")
                return t
        # If the team does not exist, create it
        payload = {'name': name}
        result = utils.get_return("/api/teams/", method="POST", payload=payload)
        print(f"Result: {result}")
        if result and not isinstance(result, dict) or not result.get("error"):
            print(f"Team '{name}' created successfully.")
            self.reload()
            return result
        else:
            print(f"Failed to create team '{name}': {result}")
            return None
    def AddUserToTeam(self, team_name, user_email):
        team_id = self.getIDfromName(team_name)
        if team_id is None:
            print(f"Team '{team_name}' does not exist.")
            return False
        user_dict = UserDict()
        user_id = user_dict.getIDfromEmail(user_email)
        if user_id is None:
            print(f"User '{user_email}' does not exist.")
            return False
        team = Team(utils.get_return(f"/api/teams/{team_id}"))
        return team.AddUser(user_id)
    def RemoveUserFromTeam(self, team_name, user_email):
        team_id = self.getIDfromName(team_name)
        if team_id is None:
            print(f"Team '{team_name}' does not exist.")
            return False
        user_dict = UserDict()
        user_id = user_dict.getIDfromEmail(user_email)
        if user_id is None:
            print(f"User '{user_email}' does not exist.")
            return False
        team = Team(utils.get_return(f"/api/teams/{team_id}"))
        return team.RemoveUser(user_id)   

class Actor:
    def __init__(self, json_actor):
        self.json_object = json_actor
    def getName(self):
        return self.json_object.get('str', '')
    def getID(self):
        return self.json_object.get('id', '')

class ActorDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.actors = [Actor(a) for a in utils.get_all_results("/api/actors/")]

    def getActors(self):
        return self.actors
    def printActors(self):
        print("Actors:")
        for a in self.actors:
            print(f"Name: {a.getName()}")
            print(f"ID: {a.getID()}")
    def getIDfromName(self, name):
        print(f"Searching for actor with name '{name}'")
        for a in self.actors:
            if a.getName() == name:
                return a.getID()
        return None
    def getNamefromID(self, id):
        for a in self.actors:
            if a.getID() == id:
                return a.getName()
        return None