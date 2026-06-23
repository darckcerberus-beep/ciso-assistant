from . import utils

class Task:
    def __init__(self, json_task):
        self.json_object = json_task
    def getJSON(self):
        return self.json_object    
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
   

class TaskDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.tasks = [Task(t) for t in utils.get_all_results("/api/task-nodes/")]

    def getTasks(self):
        return self.tasks
    def printTasks(self):
        for t in self.tasks:
            print(f"Name: {t.getName()}")
            print(f"ID: {t.getID()}")


class TaskTemplate:
    def __init__(self, json_task_template):
        self.json_object = json_task_template
    def getJSON(self):
        return self.json_object    
    def getName(self):
        return self.json_object.get('name', '')
    def getID(self):
        return self.json_object.get('id', '')
    def getIsReccurring(self):
        return self.json_object.get('is_recurrent', False)    

class TaskTemplateDict:
    def __init__(self):
        self.reload()

    def reload(self):
        self.task_templates = [TaskTemplate(tt) for tt in utils.get_all_results("/api/task-templates/")]

    def getTaskTemplates(self):
        return self.task_templates
    def printTaskTemplates(self):
        print("Task Templates:")
        for tt in self.task_templates:
            print(f"Name: {tt.getName()}")
            print(f"ID: {tt.getID()}")
            print(f"Is Recurrent: {tt.getIsReccurring()}")