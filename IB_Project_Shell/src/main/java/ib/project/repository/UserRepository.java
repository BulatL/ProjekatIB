package ib.project.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import ib.project.entity.User;

public interface UserRepository extends JpaRepository<User,Long>{
	
	User findByEmail(String email);

	List<User> findByEmailContaining(String email);
	
	List<User> findByActiveTrue();
}