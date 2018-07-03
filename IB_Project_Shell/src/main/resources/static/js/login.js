$(document).ready(function(){

	var loginBtn = $('#login');
	var registerBtn = $('#register');

	loginBtn.on('click',function(e) {
		login();
		
		e.preventDefault();
		return false;
	});
	
	registerBtn.on('click',function(e) {
		register();
		
		e.preventDefault();
		return false;
	});
	
	
});

function login(){
	var email = $('#email').val().trim();
	var password = $('#password').val().trim();
	var token = '';

	if(email=="" || password==""){
		alert("All fields must be filled.")
		return;
	}
	var data = {
		'username':email,
		'password':password
	}
	console.log(data);

	$.ajax({
		type: 'POST',
        contentType: 'application/json',
        url: 'https://localhost:8443/api/auth/login',
        data: JSON.stringify(data),
        dataType: 'json',
        crossDomain: true,
		cache: false,
		processData: false,
		success:function(response){
			var token = response.access_token;
			console.log(token + " token");
			console.log(response + " response");
			
			localStorage.setItem("token",token);
			window.location.href = "mainPage.html";
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus);
		}
	});
}

function register(){
	var email = $('#email').val().trim();
	var password = $('#password').val().trim();
	var token = '';

	if(email=="" || password==""){
		alert("All fields must be filled.")
		return;
	}
	var data = {	
			"email": email,
		    "password": password,
		    "certificate": null
		    }
	console.log(data);

	$.ajax({
		type: 'POST',
        contentType: 'application/json',
        url: 'https://localhost:8443/api/users/register',
        data: JSON.stringify(data),
        dataType: 'json',
        crossDomain: true,
		cache: false,
		processData: false,
		success:function(response){
			var token = response.access_token;
			console.log(token);
			console.log(response);
			
			localStorage.setItem("token",token);
			window.location.href = "mainPage.html";
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus);
		}
	});
}