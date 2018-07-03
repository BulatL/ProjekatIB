package ib.project.controller;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.Principal;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import org.apache.commons.io.IOUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import ib.project.dto.UserDTO;
import ib.project.entity.Authority;
import ib.project.entity.User;
import ib.project.service.AuthorityServiceInterface;
import ib.project.service.UserServiceInterface;


@RestController
@RequestMapping( value = "/api/users")
public class UserController {

	@Autowired
	UserServiceInterface userServiceInterface;
	
	@Autowired
	AuthorityServiceInterface authorityServiceInterface;
	
	@Autowired
	PasswordEncoder passwordEncoder;
	
	@GetMapping
	public ResponseEntity<List<UserDTO>> getUsers(){
		List<User> users = userServiceInterface.findAll();
		List<UserDTO> userDTO = new ArrayList<UserDTO>();
		for(User u:users) {
			userDTO.add(new UserDTO(u));
		}
		return new ResponseEntity<List<UserDTO>>(userDTO, HttpStatus.OK);
	}
	
	@RequestMapping("/logged")
    public User user(Principal user) {
        return userServiceInterface.findByEmail(user.getName());
    }
	
	@GetMapping(value = "/{id}")
	public ResponseEntity<UserDTO> getUserById(@PathVariable("id") Long id){
		User user=userServiceInterface.findOne(id);
        if(user ==null)
            return new ResponseEntity<UserDTO>(HttpStatus.NOT_FOUND);
        return  new ResponseEntity<UserDTO>(new UserDTO(user),HttpStatus.OK);
	}
	
	@GetMapping(value = "/email/{email}")
	public ResponseEntity<List<UserDTO>> getUsersByEmail(@PathVariable("email") String email){
		List<User> users = userServiceInterface.findByEmailContaining(email);
		List<UserDTO> userDTO = new ArrayList<UserDTO>();
		for(User u:users) {
			userDTO.add(new UserDTO(u));
		}
		return new ResponseEntity<List<UserDTO>>(userDTO, HttpStatus.OK);
	}
	
	@GetMapping(value = "/inactiveEmail/{email}")
	public ResponseEntity<List<UserDTO>> getInactiveUsersByEmail(@PathVariable("email") String email){
		List<User> users = userServiceInterface.findByEmailContaining(email);
		List<UserDTO> userDTO = new ArrayList<UserDTO>();
		for (User user : users) {
			if(user.isActive() == false)
				userDTO.add(new UserDTO(user));
		}
		return new ResponseEntity<List<UserDTO>>(userDTO, HttpStatus.OK);
	}
	
	
	@PostMapping(value="/register",consumes="application/json")
	public ResponseEntity<UserDTO> saveUser(@RequestBody UserDTO userDTO) {
		User user = new User();
		Authority authority = authorityServiceInterface.findByName("REGULAR");
		
		user.setEmail(userDTO.getEmail());
		user.setPassword(passwordEncoder.encode(userDTO.getPassword()));
		user.setActive(false);
		user.getUser_authorities().add(authority);
		
		user = userServiceInterface.save(user);
		return new ResponseEntity<UserDTO>(new UserDTO(user),HttpStatus.OK);
	}
	
	@PutMapping(value="/activate/{id}")
	public ResponseEntity<UserDTO> enableUser(@PathVariable("id") Long id){
		User user = userServiceInterface.findOne(id);
		if(user == null) {
			return new ResponseEntity<UserDTO>(HttpStatus.BAD_REQUEST);
		}
		user.setActive(true);
		user = userServiceInterface.save(user);
		return new ResponseEntity<UserDTO>(new UserDTO(user),HttpStatus.OK);
	}
	
	@GetMapping(value="/inactive")
	public ResponseEntity<List<UserDTO>>getInactive(){
		List<UserDTO> inactive = new ArrayList<>();
		List<User> users = userServiceInterface.findAll();
		for (User user : users) {
			if(user.isActive() == false)
				inactive.add(new UserDTO(user));
		}
		return new ResponseEntity<List<UserDTO>>(inactive,HttpStatus.OK);
	}
}