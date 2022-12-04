drop table if exists account_info;

create table account_info (
    id bigint not null auto_increment,
    is_active bit,
    password varchar(255),
    username varchar(16),
    primary key (id)
) engine=InnoDB;