import logging

from . import utils


class Task:
    """Simple wrapper around a task payload returned by the API."""

    def __init__(self, json_task):
        self.json_object = json_task

    def getJSON(self):
        return self.json_object

    def getName(self):
        return self.json_object.get("name", "")

    def getID(self):
        return self.json_object.get("id", "")


class TaskDict:
    """Collection of task nodes loaded from the API."""

    def __init__(self):
        self.reload()

    def reload(self):
        # Fetch all task nodes and wrap each payload in a Task object.
        self.tasks = [Task(task) for task in utils.get_all_results("/api/task-nodes/")]

    def getTasks(self):
        return self.tasks

    def printTasks(self):
        for task in self.tasks:
            utils.log(f"Name: {task.getName()}")
            utils.log(f"ID: {task.getID()}")


class TaskTemplate:
    """Simple wrapper around a task template payload returned by the API."""

    def __init__(self, json_task_template):
        self.json_object = json_task_template

    def getJSON(self):
        return self.json_object

    def getName(self):
        return self.json_object.get("name", "")

    def getID(self):
        return self.json_object.get("id", "")

    def getIsReccurring(self):
        # Keep the original key name to preserve compatibility with existing callers.
        return self.json_object.get("is_recurrent", False)


class TaskTemplateDict:
    """Collection of task templates loaded from the API."""

    def __init__(self):
        self.reload()

    def reload(self):
        # Fetch all task templates and wrap each payload in a TaskTemplate object.
        self.task_templates = [TaskTemplate(template) for template in utils.get_all_results("/api/task-templates/")]

    def getTaskTemplates(self):
        return self.task_templates

    def printTaskTemplates(self):
        utils.log("Task Templates:")
        for template in self.task_templates:
            utils.log(f"Name: {template.getName()}")
            utils.log(f"ID: {template.getID()}")
            utils.log(f"Is Recurrent: {template.getIsReccurring()}")