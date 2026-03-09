from sqlalchemy import create_engine, text
from app import get_database_uri

def main():
    uri = get_database_uri()
    print('DB URI:', uri)
    eng = create_engine(uri, future=True)
    with eng.connect() as conn:
        dups = conn.execute(text('''
            SELECT first_user_id, second_user_id, COUNT(*) as cnt
            FROM conversations
            WHERE first_user_id IS NOT NULL AND second_user_id IS NOT NULL
            GROUP BY first_user_id, second_user_id
            HAVING COUNT(*) > 1
        ''')).fetchall()
        if dups:
            print('Found duplicate conversation pairs:')
            for r in dups:
                print(r)
        else:
            print('No duplicate conversation pairs found')

        res = conn.execute(text("PRAGMA index_list('conversations')")).fetchall()
        print('\nIndexes on conversations:')
        for r in res:
            print(r)
        found = any('ux_conversations_pair' in (row[1] or '') for row in res)
        print('\nux_conversations_pair present?', found)

if __name__ == '__main__':
    main()
