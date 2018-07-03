package ib.project.entity;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Table;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.JoinColumn;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.FetchType;

import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.JoinTable;
import javax.persistence.ManyToMany;


@Entity
@Table(name="users")
public class User implements Serializable,UserDetails{

	@Id
	@Column(name="user_id")
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;
	
	@Column(name="email")
	private String email;
	
	@Column(name="password")
	private String password;
	
	@Column(name="certificate",nullable=true)
	private String certificate;
	
	@Column(name="active")
	private boolean active;
	
	@ManyToMany(cascade=CascadeType.ALL,fetch = FetchType.EAGER)
	@JoinTable(name="user_authority",
			joinColumns=@JoinColumn(name="user_id",referencedColumnName="user_id"),
			inverseJoinColumns = @JoinColumn(name="authority_id",referencedColumnName="authority_id"))
	private Set<Authority> user_authorities = new HashSet<>();

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getCertificate() {
		return certificate;
	}

	public void setCertificate(String certificate) {
		this.certificate = certificate;
	}
	

	public boolean isActive() {
		return active;
	}

	public void setActive(boolean active) {
		this.active = active;
	}

	@Override
    public boolean isEnabled() {
        return this.active;
    }
	
	

	@Override
	 public Collection<? extends GrantedAuthority> getAuthorities() {
		 return this.user_authorities;
	 }
	
	

	public Set<Authority> getUser_authorities() {
		return user_authorities;
	}

	public void setUser_authorities(Set<Authority> user_authorities) {
		this.user_authorities = user_authorities;
	}

	@Override
	public String getUsername() {
		
		return this.email;
	}

	@JsonIgnore
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@JsonIgnore
	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@JsonIgnore
	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}
}