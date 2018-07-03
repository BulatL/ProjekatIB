INSERT INTO users(email,password,certificate,active)VALUES('a','$2a$04$kdC9Z02xAiBrw1vBlLusbOdsfHH7EH9D8c37ZGG1VzeL62ILUNM5q',NULL,true)
INSERT INTO users(email,password,certificate,active)VALUES('b','$2a$04$kdC9Z02xAiBrw1vBlLusbOdsfHH7EH9D8c37ZGG1VzeL62ILUNM5q',NULL,true)

INSERT INTO authority(name)VALUES('ADMIN')
INSERT INTO authority(name)VALUES('REGULAR')

INSERT INTO user_authority(user_id,authority_id)VALUES(1,1)
INSERT INTO user_authority(user_id,authority_id)VALUES(2,2)