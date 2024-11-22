import { Component } from '@angular/core';
import { HttpClient, HttpClientModule } from '@angular/common/http';
import { fido2Get, fido2Create } from '@ownid/webauthn';
import { FormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { RouterOutlet } from '@angular/router';

@Component({
  selector: 'app-root',
  // imports: [RouterOutlet],
  // templateUrl: './app.component.html',
  styleUrl: './app.component.css',
  template: `
    <div>
      <h1>Passkeys Example</h1>
      <input [(ngModel)]="username" placeholder="Username" />
      <button (click)="registerStart()">Register</button>
      <button (click)="loginStart()">Login</button>
    </div>
  `,
  standalone: true,
  imports: [FormsModule, CommonModule, HttpClientModule],
})
export class AppComponent {
  username: string = '';
  constructor(private http: HttpClient) {}

  async registerStart() {
    const publicKey = await this.http
      .post('/register/start', { username: this.username })
      .toPromise();
    const fidoData = await fido2Create(publicKey, this.username);
    const response = await this.http
      .post<boolean>('/register/finish', fidoData)
      .toPromise();
    console.log(response);
  }

  async loginStart() {
    const response = await this.http
      .post('/login/start', { username: this.username })
      .toPromise();
    const options = response as PublicKeyCredentialRequestOptions;
    const assertion = await fido2Get(options, this.username);
    await this.http.post('/login/finish', assertion).toPromise();
    console.log('Login successful');
  }
}
