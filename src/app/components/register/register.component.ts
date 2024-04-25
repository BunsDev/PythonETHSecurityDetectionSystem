import { Component } from '@angular/core';
import { UserService } from '../../user.service';
import { Router } from '@angular/router';
import { FormControl, Validators, FormGroup } from '@angular/forms';
import { MatSnackBar } from '@angular/material/snack-bar';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrls: ['./register.component.css']
})
export class RegisterComponent {
  user = {
    username: '',
    email:'',
    password: ''
  };

  // Create a new FormGroup
  registerForm = new FormGroup({
    username: new FormControl('', [Validators.required]),
    email: new FormControl('', [Validators.required, Validators.email]),
    password: new FormControl('', [
      Validators.required,
      // Validators.pattern can be used to enforce complex passwords
      Validators.pattern(/^(?=[^A-Z]*[A-Z])(?=[^a-z]*[a-z])(?=[^0-9]*[0-9])(?=.*[!@#$%^&*]).{8,}$/)


    ])
  });

  private getFormControlValue(controlName: string): string {
    const control = this.registerForm.get(controlName);
    return control && typeof control.value === 'string' ? control.value.trim() : '';
  }


  constructor(
    private userService: UserService, 
    private router: Router,
    private snackBar: MatSnackBar 

  ) {}

  onRegister(): void {
    
    // Destructure the form values and ensure is string for easier access
    const username = this.getFormControlValue('username');
    const email = this.getFormControlValue('email');
    const password = this.getFormControlValue('password');

    console.log(this.registerForm.get('password')?.value);
    console.log(this.registerForm.get('password')?.errors);


    // Check if form is valid before making the request
    if (this.registerForm.valid) {
      this.userService.register(username, password, email)
      .subscribe(
        (response) => {
          console.log('Registration successful', response);
          this.snackBar.open('Registration successful.', 'Close', { 
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['my-custom-snackbar'] 
          });
          this.router.navigate(['/login']);
        },
        (error) => {
          console.error('Registration failed', error);
          this.snackBar.open('Registration failed.', 'Close', { 
            duration: 3000,
            horizontalPosition: 'center',
            verticalPosition: 'top',
            panelClass: ['my-custom-snackbar'] 
          });
        }
      );
    }
  }
}
