import { TestBed } from '@angular/core/testing';

import { EncryptionUtilService } from './encryption-util.service';

describe('EncryptionUtilService', () => {
  let service: EncryptionUtilService;

  beforeEach(() => {
    TestBed.configureTestingModule({});
    service = TestBed.inject(EncryptionUtilService);
  });

  it('should be created', () => {
    expect(service).toBeTruthy();
  });
});
