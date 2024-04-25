import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { BehaviorSubject, Observable } from 'rxjs';
import { Router } from '@angular/router'
import { tap } from 'rxjs/operators'; 

interface User {
  id: number;  // assuming id is a number
  username: string;
  // Add other user properties as needed
}

@Injectable({
  providedIn: 'root'
})
export class UserService {
  private currentUserSubject: BehaviorSubject<any>;
  public currentUser: Observable<any>;

  public get currentUserValue(): User | null {
    return this.currentUserSubject.value;
  }

  constructor(private http: HttpClient, private router: Router) {
    const storedUser = localStorage.getItem('currentUser');
    if (storedUser) {
      const user = JSON.parse(storedUser);
      // Perform any additional validation if necessary
      this.currentUserSubject = new BehaviorSubject<any>(user);
    } else {
      this.currentUserSubject = new BehaviorSubject<any>(null);
    }
    this.currentUser = this.currentUserSubject.asObservable();
  }

  // Method to call after successful login to set the current user
  public setCurrentUser(user: User): void {
    console.log('Setting current user:', user);
    localStorage.setItem('currentUser', JSON.stringify(user));
    this.currentUserSubject.next(user);
    console.log('Current User Set:', localStorage.getItem('currentUser')); 
  }

  login(username: string, password: string): Observable<any> {
    return this.http.post<any>(`/login`, { username, password }).pipe(
      tap((response: any) => {
        if (response.username) {
          // Assuming the response will now include the username
          const user: User = {
            id: response.id, // Use the actual property names returned by your API
            username: response.username,
            // Include other user properties as returned by your API
          };
          this.setCurrentUser(user); // Update the current user with the logged-in user's data
        }
      })
    );
  }

  logout() {
    // remove user from local storage to log user out
    localStorage.removeItem('currentUser');
    this.currentUserSubject.next(null);
    this.router.navigate(['/login']);
  }

  register(username: string, password: string, email: string): Observable<any> {
    return this.http.post<any>(`/register`, { username, password, email });
  }
}
