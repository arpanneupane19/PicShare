function toggle() {
	var x = document.getElementById("password-input");
	if (x.type === "password") {
	  x.type = "text";
	} else {
	  x.type = "password";
	}
  }