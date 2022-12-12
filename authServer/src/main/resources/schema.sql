drop table if exists account_info;

create table account_info (
    id bigint not null auto_increment,
    is_active bit,
    password varchar(255),
    username varchar(16) unique ,
    primary key (id)
) engine=InnoDB;

insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test0');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test1');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test2');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test3');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test4');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test5');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test6');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test7');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test8');
insert into account_info (id, is_active, password, username) values (null, true, 'asdf', 'test9');