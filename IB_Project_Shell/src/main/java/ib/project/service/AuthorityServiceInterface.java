package ib.project.service;

import ib.project.entity.Authority;

public interface AuthorityServiceInterface {
	
	Authority findByName(String name);
}