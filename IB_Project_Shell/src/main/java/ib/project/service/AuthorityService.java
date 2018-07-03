package ib.project.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import ib.project.entity.Authority;
import ib.project.repository.AuthorityRepository;

@Service
public class AuthorityService implements AuthorityServiceInterface {

	@Autowired
	AuthorityRepository authorityRepository;
	
	@Override
	public Authority findByName(String name) {
		return authorityRepository.findByName(name);
	}

}