
from .. import utils


class Task:
    """Simple wrapper around a task payload returned by the API."""

    def __init__(self, json_task):
        self.json_object = json_task

    def get_json(self):
        return self.json_object

    def get_name(self):
        return self.json_object.get("name", "")

    def get_id(self):
        return self.json_object.get("id", "")


class TaskDict:
    """Collection of task nodes loaded from the API."""

    def __init__(self):
        self.reload()

    def reload(self):
        # Fetch all task nodes and wrap each payload in a Task object.
        self.tasks = [Task(task) for task in utils.get_all_results("/api/task-nodes/", force_reload=True)]

    def get_tasks(self):
        return self.tasks

    def print_tasks(self):
        for task in self.tasks:
            utils.log(f"Name: {task.get_name()}")
            utils.log(f"ID: {task.get_id()}")


class TaskTemplate:
    """Simple wrapper around a task template payload returned by the API."""

    def __init__(self, json_task_template):
        self.json_object = json_task_template

    def get_json(self):
        return self.json_object

    def get_name(self):
        return self.json_object.get("name", "")

    def get_id(self):
        return self.json_object.get("id", "")

    def get_is_reccurring(self):
        # Keep the original key name to preserve compatibility with existing callers.
        return self.json_object.get("is_recurrent", False)


class TaskTemplateDict:
    """Collection of task templates loaded from the API."""

    def __init__(self):
        self.reload()

    def reload(self):
        # Fetch all task templates and wrap each payload in a TaskTemplate object.
        self.task_templates = [TaskTemplate(template) for template in utils.get_all_results("/api/task-templates/", force_reload=True)]

    def get_task_templates(self):
        return self.task_templates

    def print_task_templates(self):
        utils.log("Task Templates:")
        for template in self.task_templates:
            utils.log(f"Name: {template.get_name()}")
            utils.log(f"ID: {template.get_id()}")
            utils.log(f"Is Recurrent: {template.get_is_reccurring()}")

    def delete_templates_for_applied_control(self, applied_control_id):
        """Delete task templates associated with a specific applied control ID."""
        deleted_count = 0
        for template in list(self.task_templates):
            applied_controls = template.json_object.get("applied_controls", [])
            ctrl_ids = [
                c.get("id") if isinstance(c, dict) else str(c)
                for c in applied_controls
            ]
            if applied_control_id in ctrl_ids:
                res = utils.get_return(f"/api/task-templates/{template.get_id()}/", method="DELETE")
                if not (isinstance(res, dict) and res.get("error")):
                    deleted_count += 1
        if deleted_count:
            self.reload()
        return deleted_count