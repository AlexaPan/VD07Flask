from app import db, app
from app.models import User

def clear_database():
    """Очищает все таблицы в базе данных."""
    with app.app_context():
        # Получаем метаданные из базы данных
        metadata = db.metadata

        # Удаляем все данные из всех таблиц
        for table in reversed(metadata.sorted_tables):
            db.session.execute(table.delete())

        # Подтверждаем изменения
        db.session.commit()
        print("База данных успешно очищена.")

with app.app_context():
    db.create_all()

clear_database()