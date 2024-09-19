import pytest
from todo_project.models import User, Task


@pytest.fixture
def new_user():
    """Fixture para criar um novo usuário."""
    user = User(username='testuser', password='testpassword')
    return user


@pytest.fixture
def new_task(new_user):
    """Fixture para criar uma nova tarefa para o usuário."""
    task = Task(content='Test Task', user_id=new_user.id)
    return task


def test_user_creation(new_user):
    """Testa a criação de um novo usuário."""
    assert new_user.username == 'testuser'
    assert new_user.password == 'testpassword'
    assert repr(new_user) == "User('testuser')"



