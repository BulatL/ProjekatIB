$(document).ready(function() {
	var token = localStorage.getItem("token");
	console.log(token)
	if (token == "undefined" || token == null || token == "null") {
		window.location.href = "login.html";
	} else {
		currentUser();

	}
});

function currentUser(){
	var token = localStorage.getItem("token");
	$.ajax({
		url: "https://localhost:8443/api/users/logged",
		type: 'GET',
		headers: { "Authorization": "Bearer " + token},
		contentType : "application/json",
		dataType:'json',
		crossDomain: true,
		success:function(response){
			console.log("response " + response.email)
			for ( var i in response.authorities) {
				console.log(response.authorities[i].name + "authority")
				if(response.authorities[i].name=="ADMIN"){
					getInactiveUsers();
				}
				/*else{
					var searchInactiveInput = document.getElementById('searchInactiveInput');
					var searchInactiveButton = document.getElementById('searchInactiveButton');
					var usersInactive_Table = document.getElementById('usersInactive_Table');

					searchInactiveInput.style.display = "none";
					searchInactiveButton.style.display = "none";
					usersInactive_Table.style.display = "none";
				}*/
			}
			getAllUsers();
			getInactiveUsers();
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus+" "+jqXHR.status)
		}
	});
}

function getAllUsers(){
	var token = localStorage.getItem("token");
	table_header();
	$.ajax({
		url:'https://localhost:8443/api/users',
		headers:{Authorization:"Bearer " + token},
		type: 'GET',
		dataType:'json',
		crossDomain: true,
		success:function(response){
			if(response.length == 0){
				var table =  $('#users_Table');
				table.empty();
				return;
			}
			for(var i=0; i<response.length; i++) {
				var table =  $('#users_Table');
				user = response[i];
				console.log(user);
				table.append('<tr>'+
								'<td>'+user.email+'</td>'+
								'<td>'+user.active+'</td>'+
								'<td>'+'<a href='+'"./../user'+user.email+'.cer"'+'download>'+"Download"+'</a>'+'</td>'+
							'</tr>');
			}
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus+" "+jqXHR.status)
		}
	});
}

function getUsersByEmail(){
	var token = localStorage.getItem("token");
	
	var searchText = $('#searchInput').val().trim();
	if(searchText.length == 0)
		getAllUsers();
	else{
		console.log(searchText);
		table_header();
		$.ajax({
			url:'https://localhost:8443/api/users/email/' + searchText,
			headers:{Authorization:"Bearer " + token},
			type: 'GET',
			dataType: 'json',
	        crossDomain: true,
			cache: false,
			processData: false,
			success:function(response){
				if(response.length == 0){
					var table =  $('#users_Table');
					table.empty();
					table.append('<caption>All users</caption>'+
									'<tr>'+
									'<td>'+"No result for search '" + searchText+"'"+'</td>'+
								'</tr>');
					return;
				}
				for(var i=0; i<response.length; i++) {
					var table =  $('#users_Table');
					user = response[i];
					console.log(user.email);
					console.log(user);
					table.append('<tr>'+
									'<td>'+user.email+'</td>'+
									'<td>'+user.active+'</td>'+
									'<td>'+user.certificate+'</td>'+
								'</tr>');
				}
			},
			error: function (jqXHR, textStatus, errorThrown) {  
				alert(textStatus+" "+jqXHR.status)
			}
		});
	}
}

function getInactiveUsers(){
	var token = localStorage.getItem("token");
	table_header_inactive();
	$.ajax({
		url:'https://localhost:8443/api/users/inactive',
		headers:{Authorization:"Bearer " + token},
		type: 'GET',
		dataType:'json',
		crossDomain: true,
		success:function(response){
			if(response.length == 0){
				var table =  $('#usersInactive_Table');
				table.empty();
				table.append('<caption>Inactive users</caption>'+
						'<tr>'+
						'<td>'+"No inactive users"+'</td>'+
					'</tr>');
				return;
			}
			for(var i=0; i<response.length; i++) {
				var table =  $('#usersInactive_Table');
				user = response[i];
				console.log(user.email);
				table.append('<tr>'+
								'<td>'+user.email+'</td>'+
								'<td>'+user.certificate+'</td>'+
								'<td><button onclick="activateUser('+user.id+')" class="btn btn-default">Activate</button></td>'+
							'</tr>');
			}
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus+" "+jqXHR.status)
		}
	});
}

function getInactiveUsersByEmail(){
	var token = localStorage.getItem("token");
	
	var searchText = $('#searchInactiveInput').val().trim();
	if(searchText.length == 0)
		getInactiveUsers();
	else{
		console.log(searchText);
		table_header_inactive();
		$.ajax({
			url:'https://localhost:8443/api/users/inactiveEmail/' + searchText,
			headers:{Authorization:"Bearer " + token},
			type: 'GET',
			dataType: 'json',
	        crossDomain: true,
			cache: false,
			processData: false,
			success:function(response){
				if(response.length == 0){
					var table =  $('#usersInactive_Table');
					table.empty();
					table.append('<caption>All users</caption>'+
									'<tr>'+
									'<td>'+"No result for search '" + searchText+"'"+'</td>'+
								'</tr>');
					return;
				}
				for(var i=0; i<response.length; i++) {
					var table =  $('#usersInactive_Table');
					user = response[i];
					console.log(user.email);
					console.log(user);
					table.append('<tr>'+
							'<td>'+user.email+'</td>'+
							'<td>'+user.certificate+'</td>'+
							'<td><button onclick="activateUser('+user.id+')" class="btn btn-default">Activate</button></td>'+
						'</tr>');
				}
			},
			error: function (jqXHR, textStatus, errorThrown) {  
				alert(textStatus+" "+jqXHR.status)
			}
		});
	}
}

function activateUser(id){
	var token = localStorage.getItem("token");
	console.log(id)
	$.ajax({
		type: 'PUT',
		headers:{"Authorization" :"Bearer " + token},
        url: 'https://localhost:8443/api/users/activate/'+id,
        dataType: 'json',
        crossDomain: true,
		cache: false,
		processData: false,
		success:function(response){
			alert("User activated.");
			getAllUsers();
			getInactiveUsers();
		},
		error: function (jqXHR, textStatus, errorThrown) {  
			alert(textStatus+" "+jqXHR.status)
		}
	});
}

function table_header(){
	var table = $('#users_Table');
	table.empty();
	table.append('<caption>All users</caption>'+
				'<tr>'+
					'<th>Email</th>'+
					'<th>Active</th>'+
					'<th>Certificate</th>'+
				'</tr>');
}

function table_header_inactive(){
	var table = $('#usersInactive_Table');
	table.empty();
	table.append('<caption>Inactive users</caption>'+
				'<tr>'+
					'<th>Email</th>'+
					'<th>Certificate</th>'+
					'<th>Activate</th>'+
				'</tr>');
}

function logout(){
	localStorage.removeItem("token");
	window.location.replace("https://localhost:8443/login.html");
}