import { Component } from '@angular/core';
import { UserService } from '../../user.service';
import { Router } from '@angular/router';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
  selector: 'app-login',
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.css']
})
export class LoginComponent {
  credentials = {
    username: '',
    password: ''
  };

  errorMessage: string = '';

  constructor(
    private userService: UserService, 
    private router: Router,
    private snackBar: MatSnackBar 

  ) {}

  onLogin(): void {
    this.userService.login(this.credentials.username, this.credentials.password)
      .subscribe(
        (response) => {
          console.log('Logged in successfully');
          this.snackBar.open('Logged in successfully.', 'Close', { 
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['my-custom-snackbar'] 
          });
          this.router.navigate(['/dashboard']);
        },
        (error) => {
          console.error('Login failed', error);
          this.errorMessage = 'Incorrect username or password.'; // Set the error message of login fail
        }
      );
  }
  
}
