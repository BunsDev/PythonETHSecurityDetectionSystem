import { Component } from '@angular/core';

@Component({
  selector: 'app-settings',
  templateUrl: './settings.component.html',
  styleUrls: ['./settings.component.css']
})
export class SettingsComponent {
  settings = {
    securityAlerts: true,
    severityLevel: 5,
    etherscanApiKey: '',
    theme: 'light',
    // Add other settings variables here
  };

  saveSettings() {
    // Here you would save settings to a database or local storage
    console.log('Settings saved', this.settings);
  }
}
