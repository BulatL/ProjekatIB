package ib.project.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import ib.project.entity.User;
import ib.project.repository.UserRepository;

@Service
public class UserService implements UserServiceInterface{

	@Autowired
	UserRepository userRepository;
	
	@Override
	public List<User> findAll() {
		return userRepository.findAll();
	}

	@Override
	public User findOne(Long userId) {
		return userRepository.findOne(userId);
	}

	@Override
	public User findByEmail(String email) {
		return userRepository.findByEmail(email);
	}

	@Override
	public List<User> findByActiveTrue() {
		List<User> users = userRepository.findByActiveTrue();
		return users;
	}

	@Override
	public User save(User user) {
		return userRepository.save(user);
	}
	
	@Override
	public List<User> findByEmailContaining(String email) {
		List<User> users = userRepository.findByEmailContaining(email);
		return users;
	}

}
