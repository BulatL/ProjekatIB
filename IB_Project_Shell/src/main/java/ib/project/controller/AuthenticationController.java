package ib.project.controller;

import java.io.IOException;
import java.security.Principal;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.mobile.device.Device;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import ib.project.entity.User;
import ib.project.entity.UserTokenState;
import ib.project.security.JwtAuthenticationRequest;
import ib.project.security.TokenHelper;
import ib.project.service.CustomUserDetailService;


//KOntroler zaduzen za autentifikaciju korisnika
//Na osnovni URL se dodaje /auth kako bi se pristupilo citavom kontroleru
//Ukoliko je aplikacija podignuta lokalno => localhost:8080/api
@RestController
@RequestMapping( value = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE )
@CrossOrigin("*")
public class AuthenticationController {

  @Autowired
  TokenHelper tokenHelper;

  @Autowired
  private AuthenticationManager authenticationManager;

  @Autowired
  private CustomUserDetailService userDetailsService;
  

  //Ukoliko je aplikacija podignuta lokalno => localhost:8080/api/login
  //Metodi se prosledjuje objekat u kom se nalazi username i password korisnika
  @RequestMapping(value = "/login", method = RequestMethod.POST)
  public ResponseEntity<?> createAuthenticationToken(
          @RequestBody JwtAuthenticationRequest authenticationRequest,
          HttpServletResponse response
  ) throws AuthenticationException, IOException {

      // Izvrsavanje security dela
      final Authentication authentication = authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(
                      authenticationRequest.getUsername(),
                      authenticationRequest.getPassword()
              )
      );

      // Ubaci username + password u kontext
      SecurityContextHolder.getContext().setAuthentication(authentication);

      // Kreiraj token
      User user = (User)authentication.getPrincipal();
      String jws = tokenHelper.generateToken(user.getUsername());
      
      // Vrati token kao odgovor na uspesno autentifikaciju
      return ResponseEntity.ok(new UserTokenState(jws));
  }


  @RequestMapping(value = "/change-password", method = RequestMethod.POST)
  @PreAuthorize("hasRole('USER')")
  public ResponseEntity<?> changePassword(@RequestBody PasswordChanger passwordChanger) {
      userDetailsService.changePassword(passwordChanger.oldPassword, passwordChanger.newPassword);
      Map<String, String> result = new HashMap<>();
      result.put( "result", "success" );
      return ResponseEntity.accepted().body(result);
  }

  static class PasswordChanger {
      public String oldPassword;
      public String newPassword;
  }
}