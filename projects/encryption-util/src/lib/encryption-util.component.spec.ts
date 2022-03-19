import { ComponentFixture, TestBed } from '@angular/core/testing';

import { EncryptionUtilComponent } from './encryption-util.component';

describe('EncryptionUtilComponent', () => {
  let component: EncryptionUtilComponent;
  let fixture: ComponentFixture<EncryptionUtilComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      declarations: [ EncryptionUtilComponent ]
    })
    .compileComponents();
  });

  beforeEach(() => {
    fixture = TestBed.createComponent(EncryptionUtilComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
