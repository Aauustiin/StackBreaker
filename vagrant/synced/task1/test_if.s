
test_if:     file format elf32-i386


Disassembly of section .init:

000003b4 <_init>:
 3b4:	53                   	push   %ebx
 3b5:	83 ec 08             	sub    $0x8,%esp
 3b8:	e8 c3 00 00 00       	call   480 <__x86.get_pc_thunk.bx>
 3bd:	81 c3 13 1c 00 00    	add    $0x1c13,%ebx
 3c3:	8b 83 24 00 00 00    	mov    0x24(%ebx),%eax
 3c9:	85 c0                	test   %eax,%eax
 3cb:	74 05                	je     3d2 <_init+0x1e>
 3cd:	e8 66 00 00 00       	call   438 <__gmon_start__@plt>
 3d2:	83 c4 08             	add    $0x8,%esp
 3d5:	5b                   	pop    %ebx
 3d6:	c3                   	ret    

Disassembly of section .plt:

000003e0 <.plt>:
 3e0:	ff b3 04 00 00 00    	pushl  0x4(%ebx)
 3e6:	ff a3 08 00 00 00    	jmp    *0x8(%ebx)
 3ec:	00 00                	add    %al,(%eax)
	...

000003f0 <time@plt>:
 3f0:	ff a3 0c 00 00 00    	jmp    *0xc(%ebx)
 3f6:	68 00 00 00 00       	push   $0x0
 3fb:	e9 e0 ff ff ff       	jmp    3e0 <.plt>

00000400 <srand@plt>:
 400:	ff a3 10 00 00 00    	jmp    *0x10(%ebx)
 406:	68 08 00 00 00       	push   $0x8
 40b:	e9 d0 ff ff ff       	jmp    3e0 <.plt>

00000410 <__libc_start_main@plt>:
 410:	ff a3 14 00 00 00    	jmp    *0x14(%ebx)
 416:	68 10 00 00 00       	push   $0x10
 41b:	e9 c0 ff ff ff       	jmp    3e0 <.plt>

00000420 <rand@plt>:
 420:	ff a3 18 00 00 00    	jmp    *0x18(%ebx)
 426:	68 18 00 00 00       	push   $0x18
 42b:	e9 b0 ff ff ff       	jmp    3e0 <.plt>

Disassembly of section .plt.got:

00000430 <__cxa_finalize@plt>:
 430:	ff a3 20 00 00 00    	jmp    *0x20(%ebx)
 436:	66 90                	xchg   %ax,%ax

00000438 <__gmon_start__@plt>:
 438:	ff a3 24 00 00 00    	jmp    *0x24(%ebx)
 43e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

00000440 <_start>:
 440:	31 ed                	xor    %ebp,%ebp
 442:	5e                   	pop    %esi
 443:	89 e1                	mov    %esp,%ecx
 445:	83 e4 f0             	and    $0xfffffff0,%esp
 448:	50                   	push   %eax
 449:	54                   	push   %esp
 44a:	52                   	push   %edx
 44b:	e8 22 00 00 00       	call   472 <_start+0x32>
 450:	81 c3 80 1b 00 00    	add    $0x1b80,%ebx
 456:	8d 83 a0 e6 ff ff    	lea    -0x1960(%ebx),%eax
 45c:	50                   	push   %eax
 45d:	8d 83 40 e6 ff ff    	lea    -0x19c0(%ebx),%eax
 463:	50                   	push   %eax
 464:	51                   	push   %ecx
 465:	56                   	push   %esi
 466:	ff b3 28 00 00 00    	pushl  0x28(%ebx)
 46c:	e8 9f ff ff ff       	call   410 <__libc_start_main@plt>
 471:	f4                   	hlt    
 472:	8b 1c 24             	mov    (%esp),%ebx
 475:	c3                   	ret    
 476:	66 90                	xchg   %ax,%ax
 478:	66 90                	xchg   %ax,%ax
 47a:	66 90                	xchg   %ax,%ax
 47c:	66 90                	xchg   %ax,%ax
 47e:	66 90                	xchg   %ax,%ax

00000480 <__x86.get_pc_thunk.bx>:
 480:	8b 1c 24             	mov    (%esp),%ebx
 483:	c3                   	ret    
 484:	66 90                	xchg   %ax,%ax
 486:	66 90                	xchg   %ax,%ax
 488:	66 90                	xchg   %ax,%ax
 48a:	66 90                	xchg   %ax,%ax
 48c:	66 90                	xchg   %ax,%ax
 48e:	66 90                	xchg   %ax,%ax

00000490 <deregister_tm_clones>:
 490:	e8 e4 00 00 00       	call   579 <__x86.get_pc_thunk.dx>
 495:	81 c2 3b 1b 00 00    	add    $0x1b3b,%edx
 49b:	8d 8a 38 00 00 00    	lea    0x38(%edx),%ecx
 4a1:	8d 82 38 00 00 00    	lea    0x38(%edx),%eax
 4a7:	39 c8                	cmp    %ecx,%eax
 4a9:	74 1d                	je     4c8 <deregister_tm_clones+0x38>
 4ab:	8b 82 1c 00 00 00    	mov    0x1c(%edx),%eax
 4b1:	85 c0                	test   %eax,%eax
 4b3:	74 13                	je     4c8 <deregister_tm_clones+0x38>
 4b5:	55                   	push   %ebp
 4b6:	89 e5                	mov    %esp,%ebp
 4b8:	83 ec 14             	sub    $0x14,%esp
 4bb:	51                   	push   %ecx
 4bc:	ff d0                	call   *%eax
 4be:	83 c4 10             	add    $0x10,%esp
 4c1:	c9                   	leave  
 4c2:	c3                   	ret    
 4c3:	90                   	nop
 4c4:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 4c8:	f3 c3                	repz ret 
 4ca:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

000004d0 <register_tm_clones>:
 4d0:	e8 a4 00 00 00       	call   579 <__x86.get_pc_thunk.dx>
 4d5:	81 c2 fb 1a 00 00    	add    $0x1afb,%edx
 4db:	55                   	push   %ebp
 4dc:	8d 8a 38 00 00 00    	lea    0x38(%edx),%ecx
 4e2:	8d 82 38 00 00 00    	lea    0x38(%edx),%eax
 4e8:	29 c8                	sub    %ecx,%eax
 4ea:	89 e5                	mov    %esp,%ebp
 4ec:	53                   	push   %ebx
 4ed:	c1 f8 02             	sar    $0x2,%eax
 4f0:	89 c3                	mov    %eax,%ebx
 4f2:	83 ec 04             	sub    $0x4,%esp
 4f5:	c1 eb 1f             	shr    $0x1f,%ebx
 4f8:	01 d8                	add    %ebx,%eax
 4fa:	d1 f8                	sar    %eax
 4fc:	74 14                	je     512 <register_tm_clones+0x42>
 4fe:	8b 92 2c 00 00 00    	mov    0x2c(%edx),%edx
 504:	85 d2                	test   %edx,%edx
 506:	74 0a                	je     512 <register_tm_clones+0x42>
 508:	83 ec 08             	sub    $0x8,%esp
 50b:	50                   	push   %eax
 50c:	51                   	push   %ecx
 50d:	ff d2                	call   *%edx
 50f:	83 c4 10             	add    $0x10,%esp
 512:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 515:	c9                   	leave  
 516:	c3                   	ret    
 517:	89 f6                	mov    %esi,%esi
 519:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000520 <__do_global_dtors_aux>:
 520:	55                   	push   %ebp
 521:	89 e5                	mov    %esp,%ebp
 523:	53                   	push   %ebx
 524:	e8 57 ff ff ff       	call   480 <__x86.get_pc_thunk.bx>
 529:	81 c3 a7 1a 00 00    	add    $0x1aa7,%ebx
 52f:	83 ec 04             	sub    $0x4,%esp
 532:	80 bb 38 00 00 00 00 	cmpb   $0x0,0x38(%ebx)
 539:	75 27                	jne    562 <__do_global_dtors_aux+0x42>
 53b:	8b 83 20 00 00 00    	mov    0x20(%ebx),%eax
 541:	85 c0                	test   %eax,%eax
 543:	74 11                	je     556 <__do_global_dtors_aux+0x36>
 545:	83 ec 0c             	sub    $0xc,%esp
 548:	ff b3 34 00 00 00    	pushl  0x34(%ebx)
 54e:	e8 dd fe ff ff       	call   430 <__cxa_finalize@plt>
 553:	83 c4 10             	add    $0x10,%esp
 556:	e8 35 ff ff ff       	call   490 <deregister_tm_clones>
 55b:	c6 83 38 00 00 00 01 	movb   $0x1,0x38(%ebx)
 562:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 565:	c9                   	leave  
 566:	c3                   	ret    
 567:	89 f6                	mov    %esi,%esi
 569:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000570 <frame_dummy>:
 570:	55                   	push   %ebp
 571:	89 e5                	mov    %esp,%ebp
 573:	5d                   	pop    %ebp
 574:	e9 57 ff ff ff       	jmp    4d0 <register_tm_clones>

00000579 <__x86.get_pc_thunk.dx>:
 579:	8b 14 24             	mov    (%esp),%edx
 57c:	c3                   	ret    

0000057d <rec_func>:
 57d:	55                   	push   %ebp
 57e:	89 e5                	mov    %esp,%ebp
 580:	83 ec 08             	sub    $0x8,%esp
 583:	e8 7a 00 00 00       	call   602 <__x86.get_pc_thunk.ax>
 588:	05 48 1a 00 00       	add    $0x1a48,%eax
 58d:	8b 45 08             	mov    0x8(%ebp),%eax
 590:	83 e8 01             	sub    $0x1,%eax
 593:	83 ec 0c             	sub    $0xc,%esp
 596:	50                   	push   %eax
 597:	e8 e1 ff ff ff       	call   57d <rec_func>
 59c:	83 c4 10             	add    $0x10,%esp
 59f:	90                   	nop
 5a0:	c9                   	leave  
 5a1:	c3                   	ret    

000005a2 <main>:
 5a2:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 5a6:	83 e4 f0             	and    $0xfffffff0,%esp
 5a9:	ff 71 fc             	pushl  -0x4(%ecx)
 5ac:	55                   	push   %ebp
 5ad:	89 e5                	mov    %esp,%ebp
 5af:	53                   	push   %ebx
 5b0:	51                   	push   %ecx
 5b1:	83 ec 10             	sub    $0x10,%esp
 5b4:	e8 c7 fe ff ff       	call   480 <__x86.get_pc_thunk.bx>
 5b9:	81 c3 17 1a 00 00    	add    $0x1a17,%ebx
 5bf:	83 ec 0c             	sub    $0xc,%esp
 5c2:	6a 00                	push   $0x0
 5c4:	e8 27 fe ff ff       	call   3f0 <time@plt>
 5c9:	83 c4 10             	add    $0x10,%esp
 5cc:	83 ec 0c             	sub    $0xc,%esp
 5cf:	50                   	push   %eax
 5d0:	e8 2b fe ff ff       	call   400 <srand@plt>
 5d5:	83 c4 10             	add    $0x10,%esp
 5d8:	e8 43 fe ff ff       	call   420 <rand@plt>
 5dd:	89 45 f4             	mov    %eax,-0xc(%ebp)
 5e0:	83 7d f4 00          	cmpl   $0x0,-0xc(%ebp)
 5e4:	74 0d                	je     5f3 <main+0x51>
 5e6:	83 ec 0c             	sub    $0xc,%esp
 5e9:	6a 0a                	push   $0xa
 5eb:	e8 8d ff ff ff       	call   57d <rec_func>
 5f0:	83 c4 10             	add    $0x10,%esp
 5f3:	b8 00 00 00 00       	mov    $0x0,%eax
 5f8:	8d 65 f8             	lea    -0x8(%ebp),%esp
 5fb:	59                   	pop    %ecx
 5fc:	5b                   	pop    %ebx
 5fd:	5d                   	pop    %ebp
 5fe:	8d 61 fc             	lea    -0x4(%ecx),%esp
 601:	c3                   	ret    

00000602 <__x86.get_pc_thunk.ax>:
 602:	8b 04 24             	mov    (%esp),%eax
 605:	c3                   	ret    
 606:	66 90                	xchg   %ax,%ax
 608:	66 90                	xchg   %ax,%ax
 60a:	66 90                	xchg   %ax,%ax
 60c:	66 90                	xchg   %ax,%ax
 60e:	66 90                	xchg   %ax,%ax

00000610 <__libc_csu_init>:
 610:	55                   	push   %ebp
 611:	57                   	push   %edi
 612:	56                   	push   %esi
 613:	53                   	push   %ebx
 614:	e8 67 fe ff ff       	call   480 <__x86.get_pc_thunk.bx>
 619:	81 c3 b7 19 00 00    	add    $0x19b7,%ebx
 61f:	83 ec 0c             	sub    $0xc,%esp
 622:	8b 6c 24 28          	mov    0x28(%esp),%ebp
 626:	8d b3 04 ff ff ff    	lea    -0xfc(%ebx),%esi
 62c:	e8 83 fd ff ff       	call   3b4 <_init>
 631:	8d 83 00 ff ff ff    	lea    -0x100(%ebx),%eax
 637:	29 c6                	sub    %eax,%esi
 639:	c1 fe 02             	sar    $0x2,%esi
 63c:	85 f6                	test   %esi,%esi
 63e:	74 25                	je     665 <__libc_csu_init+0x55>
 640:	31 ff                	xor    %edi,%edi
 642:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 648:	83 ec 04             	sub    $0x4,%esp
 64b:	55                   	push   %ebp
 64c:	ff 74 24 2c          	pushl  0x2c(%esp)
 650:	ff 74 24 2c          	pushl  0x2c(%esp)
 654:	ff 94 bb 00 ff ff ff 	call   *-0x100(%ebx,%edi,4)
 65b:	83 c7 01             	add    $0x1,%edi
 65e:	83 c4 10             	add    $0x10,%esp
 661:	39 fe                	cmp    %edi,%esi
 663:	75 e3                	jne    648 <__libc_csu_init+0x38>
 665:	83 c4 0c             	add    $0xc,%esp
 668:	5b                   	pop    %ebx
 669:	5e                   	pop    %esi
 66a:	5f                   	pop    %edi
 66b:	5d                   	pop    %ebp
 66c:	c3                   	ret    
 66d:	8d 76 00             	lea    0x0(%esi),%esi

00000670 <__libc_csu_fini>:
 670:	f3 c3                	repz ret 

Disassembly of section .fini:

00000674 <_fini>:
 674:	53                   	push   %ebx
 675:	83 ec 08             	sub    $0x8,%esp
 678:	e8 03 fe ff ff       	call   480 <__x86.get_pc_thunk.bx>
 67d:	81 c3 53 19 00 00    	add    $0x1953,%ebx
 683:	83 c4 08             	add    $0x8,%esp
 686:	5b                   	pop    %ebx
 687:	c3                   	ret    
