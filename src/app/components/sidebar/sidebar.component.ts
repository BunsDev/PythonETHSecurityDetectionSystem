import { Component } from '@angular/core';
import { UserService } from '../../user.service';
import { ChangeDetectorRef } from '@angular/core';

@Component({
  selector: 'app-sidebar',
  templateUrl: './sidebar.component.html',
  styleUrl: './sidebar.component.css'
})
export class SidebarComponent {
  private cdr: ChangeDetectorRef;
  // Inject UserService in the constructor
  constructor(public userService: UserService, cdr: ChangeDetectorRef) { 
    this.cdr = cdr; 
  }

  get isLoggedIn(): boolean {
    return this.userService.currentUserValue != null;
  }

  logout() {
    this.userService.logout();
  }

  // Call this method where needed to update the view
  private updateView() {
    this.cdr.detectChanges();
  }
}
