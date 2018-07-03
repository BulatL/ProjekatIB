package ib.project.service;

import java.util.List;

import ib.project.entity.User;


public interface UserServiceInterface {

	List<User> findAll();
	
	User findOne(Long userId);
	
	User findByEmail(String email);
	
	List<User> findByActiveTrue();
	
	User save(User user);
	
	List<User> findByEmailContaining(String email);
}