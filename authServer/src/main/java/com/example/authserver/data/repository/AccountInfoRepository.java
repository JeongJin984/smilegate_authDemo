package com.example.authserver.data.repository;

import com.example.authserver.data.entity.AccountInfo;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface AccountInfoRepository extends CrudRepository<AccountInfo, Long>, AccountInfoRepositoryCustom {
    @Query("select ai from AccountInfo ai where ai.username = :username")
    AccountInfo findAccountInfoByUsername(@Param("username") String username);
    AccountInfo save(AccountInfo accountInfo);
}
