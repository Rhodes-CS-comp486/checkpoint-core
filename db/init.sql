CREATE TABLE Users
(
    username VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL, 
    full_name VARCHAR(255),
    PRIMARY KEY (username)
);
CREATE TABLE equipment
(
    id VARCHAR(255), NOT NULL,
    PRIMARY KEY (id)
);