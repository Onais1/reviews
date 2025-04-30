import os
import subprocess
import sys

def setup_app():
    print("Setting up The Skate Sanctuary Feedback App...")

    # Determine the project directory (where setup.py is located)
    project_dir = os.path.abspath(os.path.dirname(__file__))
    instance_dir = os.path.join(project_dir, 'instance')
    db_path = os.path.join(instance_dir, 'reviews.db').replace('\\', '/')
    migrations_dir = os.path.join(project_dir, 'migrations')

    # Create instance directory if it doesn't exist
    os.makedirs(instance_dir, exist_ok=True)
    print(f"Ensured instance directory exists at: {instance_dir}")

    # Update alembic.ini with the correct database path
    alembic_ini_path = os.path.join(migrations_dir, 'alembic.ini')
    db_uri = f'sqlite:///{db_path}'
    
    # Check if migrations directory exists; if not, initialize it
    if not os.path.exists(migrations_dir):
        print("Initializing migrations...")
        subprocess.run(['flask', 'db', 'init'], check=True)
    
    # Read the current alembic.ini
    if os.path.exists(alembic_ini_path):
        with open(alembic_ini_path, 'r') as f:
            lines = f.readlines()
        
        # Update the sqlalchemy.url line
        with open(alembic_ini_path, 'w') as f:
            for line in lines:
                if line.strip().startswith('sqlalchemy.url'):
                    f.write(f'sqlalchemy.url = {db_uri}\n')
                else:
                    f.write(line)
        print(f"Updated alembic.ini with database URI: {db_uri}")
    else:
        print("Error: alembic.ini not found. Please run 'flask db init' manually.")
        sys.exit(1)

    # Run migrations
    print("Running database migrations...")
    subprocess.run(['flask', 'db', 'migrate', '-m', 'Setup database'], check=True)
    subprocess.run(['flask', 'db', 'upgrade'], check=True)
    print("Database setup complete!")

if __name__ == "__main__":
    setup_app()