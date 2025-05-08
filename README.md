# Checkpoint-Core

## Project Description

Checkpoint Core is the database and application logic backend of the Checkpoint equipment check-out web service. It provides secure storage and hosting for essential equipment and user data to allow seamless check-out and check-in for equipment held by the computer science department for use by students and faculty, such as robotics equipment and computers. Via requests from Checkpoint Core's counterpart Checkpoint Web, equipment can be reserved for pick-up and assigned to individuals. Administrator users can retrieve and store equipment status such as current user assignment and degree of wear-and-tear for the purpose of equipment refresh and replacement, to ensure the Rhodes community has access to the best available materials. Checkpoint Core, alongside its counterpart, Checkpoint Web, allows the Computer Science department faculty to more easily manage, maintain, and update its cache of equipment. Checkpoint Core runs as a containerized microservice that was built using Python, the FastAPI framework, and Docker. It is hosted using the uvicorn web server and uses a PostgreSQL database.

### Key Features:

- User authentication system with support for admin and regular users
- Catalog of available equipment with details and status tracking
- Borrowing and returning system with automatic updates to availability
- Role-based permissions and admin-only actions (e.g. equipment management)
- Automated email notifications and reminders for due dates and overdue items
- Dockerized setup with isolated containers for server and PostgreSQL database
- Interactive API documentation available at `/docs` via Swagger UI

### System Diagram:

![image](https://github.com/user-attachments/assets/4ceb7980-4f0d-46b8-9e82-1c36a12ebe7b)


## Project Dependencies

The following libraries are specified in `requirements.txt`:

- `fastapi` – API framework
- `uvicorn` – ASGI server for serving FastAPI
- `python-multipart` – for handling file uploads
- `PyJWT` – JSON Web Token-based authentication
- `passlib` – password hashing
- `sqlalchemy` and `sqlmodel` – database ORM and model layer
- `psycopg2-binary` – PostgreSQL driver
- `pycryptodome` – for cryptographic operations
- `fastapi-mail` – for sending email notifications
- `apscheduler` – for scheduled tasks (e.g. reminders)
- `pytz` – timezone support for scheduling

Runtime Requirements:

- **Python 3.x**
- **Docker Desktop** – for container orchestration
- **Docker Compose** – builds and runs containers for the server and PostgreSQL database

Backend Services:

- **PostgreSQL** – used as the relational database to store user and equipment data
- **Email Service** – configured via `fastapi-mail` to send notifications (e.g., check-in/out alerts)

## Quickstart guide

Requirements:
The only requirement to run Checkpoint Core is Docker Desktop, which can be downloaded and installed free for personal use at https://www.docker.com/products/docker-desktop/ 

All other requirements are pulled via docker, and are listed in requirements.txt

Follow the installation steps carefully, as additional setup may be required depending on your operating system. If you're running Windows, you will need to have Windows Subsystem for Linux enabled. If you're running Mac, you may need a VM such as Multipass. There are many resources online to get Docker running on your machine.

Windows users, to verify that Docker is configured correctly, check that under Settings/Resources/WSL integration, "Enable integration with my default WSL distro" is checked.

Checkpoint Core runs a linux based python image with a nested postgres image to host the database. The database you launch will be seeded with a handful of fake entries in each table. To launch without this seed data, comment out the seed data section at the bottom of src/main.py

If you plan to add any sensitive data to your database **be sure to edit db/password.txt** and change it to a secure password before launching!

Once you have Docker installed properly, to run Checkpoint Core, first run Docker Desktop as an administrator. Then, open the project directory for Checkpoint Core and run the command:

`docker compose up --build`

This will build and launch the image and host it on your localhost port 8000. It may take up to several minutes to build the first time, so be patient. To access the app in your browser, visit http://localhost:8000/

To access the app via the FastAPI documentation page, visit http://localhost:8000/docs#/

The FastAPI docs page will show you all the commands which can be sent to the app and what they return. Use the seeded User data to log in and try the various commands. Some commands require admin authentication.

If you ever need to reload the database (if you change anything about the postgres instance, including the password), run the command:

`docker compose down --volumes`

This will destroy your container and its associated volumes, giving you a fresh start. Be advised that this will delete ALL data in the database permanently.

The counterpart project to Checkpoint-Core is the web app, Checkpoint-Web. You can access the repository for Checkpoint-Web at https://github.com/Rhodes-CS-comp486/checkpoint-web
