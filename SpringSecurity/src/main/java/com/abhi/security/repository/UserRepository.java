package com.abhi.security.repository;

import com.abhi.security.model.EndUser;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.Optional;

public interface UserRepository extends JpaRepository<EndUser, Long> {
    Optional<EndUser> findByUseremail(String useremail);

	  Optional<EndUser>  findByUsername(String string);
}