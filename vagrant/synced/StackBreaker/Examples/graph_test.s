
graph_test:     file format elf32-i386


Disassembly of section .init:

000003f4 <_init>:
 3f4:	53                   	push   %ebx
 3f5:	83 ec 08             	sub    $0x8,%esp
 3f8:	e8 e3 00 00 00       	call   4e0 <__x86.get_pc_thunk.bx>
 3fd:	81 c3 cb 1b 00 00    	add    $0x1bcb,%ebx
 403:	8b 83 2c 00 00 00    	mov    0x2c(%ebx),%eax
 409:	85 c0                	test   %eax,%eax
 40b:	74 05                	je     412 <_init+0x1e>
 40d:	e8 86 00 00 00       	call   498 <__gmon_start__@plt>
 412:	83 c4 08             	add    $0x8,%esp
 415:	5b                   	pop    %ebx
 416:	c3                   	ret    

Disassembly of section .plt:

00000420 <.plt>:
 420:	ff b3 04 00 00 00    	pushl  0x4(%ebx)
 426:	ff a3 08 00 00 00    	jmp    *0x8(%ebx)
 42c:	00 00                	add    %al,(%eax)
	...

00000430 <time@plt>:
 430:	ff a3 0c 00 00 00    	jmp    *0xc(%ebx)
 436:	68 00 00 00 00       	push   $0x0
 43b:	e9 e0 ff ff ff       	jmp    420 <.plt>

00000440 <strcpy@plt>:
 440:	ff a3 10 00 00 00    	jmp    *0x10(%ebx)
 446:	68 08 00 00 00       	push   $0x8
 44b:	e9 d0 ff ff ff       	jmp    420 <.plt>

00000450 <puts@plt>:
 450:	ff a3 14 00 00 00    	jmp    *0x14(%ebx)
 456:	68 10 00 00 00       	push   $0x10
 45b:	e9 c0 ff ff ff       	jmp    420 <.plt>

00000460 <srand@plt>:
 460:	ff a3 18 00 00 00    	jmp    *0x18(%ebx)
 466:	68 18 00 00 00       	push   $0x18
 46b:	e9 b0 ff ff ff       	jmp    420 <.plt>

00000470 <__libc_start_main@plt>:
 470:	ff a3 1c 00 00 00    	jmp    *0x1c(%ebx)
 476:	68 20 00 00 00       	push   $0x20
 47b:	e9 a0 ff ff ff       	jmp    420 <.plt>

00000480 <rand@plt>:
 480:	ff a3 20 00 00 00    	jmp    *0x20(%ebx)
 486:	68 28 00 00 00       	push   $0x28
 48b:	e9 90 ff ff ff       	jmp    420 <.plt>

Disassembly of section .plt.got:

00000490 <__cxa_finalize@plt>:
 490:	ff a3 28 00 00 00    	jmp    *0x28(%ebx)
 496:	66 90                	xchg   %ax,%ax

00000498 <__gmon_start__@plt>:
 498:	ff a3 2c 00 00 00    	jmp    *0x2c(%ebx)
 49e:	66 90                	xchg   %ax,%ax

Disassembly of section .text:

000004a0 <_start>:
 4a0:	31 ed                	xor    %ebp,%ebp
 4a2:	5e                   	pop    %esi
 4a3:	89 e1                	mov    %esp,%ecx
 4a5:	83 e4 f0             	and    $0xfffffff0,%esp
 4a8:	50                   	push   %eax
 4a9:	54                   	push   %esp
 4aa:	52                   	push   %edx
 4ab:	e8 22 00 00 00       	call   4d2 <_start+0x32>
 4b0:	81 c3 18 1b 00 00    	add    $0x1b18,%ebx
 4b6:	8d 83 98 e7 ff ff    	lea    -0x1868(%ebx),%eax
 4bc:	50                   	push   %eax
 4bd:	8d 83 38 e7 ff ff    	lea    -0x18c8(%ebx),%eax
 4c3:	50                   	push   %eax
 4c4:	51                   	push   %ecx
 4c5:	56                   	push   %esi
 4c6:	ff b3 30 00 00 00    	pushl  0x30(%ebx)
 4cc:	e8 9f ff ff ff       	call   470 <__libc_start_main@plt>
 4d1:	f4                   	hlt    
 4d2:	8b 1c 24             	mov    (%esp),%ebx
 4d5:	c3                   	ret    
 4d6:	66 90                	xchg   %ax,%ax
 4d8:	66 90                	xchg   %ax,%ax
 4da:	66 90                	xchg   %ax,%ax
 4dc:	66 90                	xchg   %ax,%ax
 4de:	66 90                	xchg   %ax,%ax

000004e0 <__x86.get_pc_thunk.bx>:
 4e0:	8b 1c 24             	mov    (%esp),%ebx
 4e3:	c3                   	ret    
 4e4:	66 90                	xchg   %ax,%ax
 4e6:	66 90                	xchg   %ax,%ax
 4e8:	66 90                	xchg   %ax,%ax
 4ea:	66 90                	xchg   %ax,%ax
 4ec:	66 90                	xchg   %ax,%ax
 4ee:	66 90                	xchg   %ax,%ax

000004f0 <deregister_tm_clones>:
 4f0:	e8 e4 00 00 00       	call   5d9 <__x86.get_pc_thunk.dx>
 4f5:	81 c2 d3 1a 00 00    	add    $0x1ad3,%edx
 4fb:	8d 8a 40 00 00 00    	lea    0x40(%edx),%ecx
 501:	8d 82 40 00 00 00    	lea    0x40(%edx),%eax
 507:	39 c8                	cmp    %ecx,%eax
 509:	74 1d                	je     528 <deregister_tm_clones+0x38>
 50b:	8b 82 24 00 00 00    	mov    0x24(%edx),%eax
 511:	85 c0                	test   %eax,%eax
 513:	74 13                	je     528 <deregister_tm_clones+0x38>
 515:	55                   	push   %ebp
 516:	89 e5                	mov    %esp,%ebp
 518:	83 ec 14             	sub    $0x14,%esp
 51b:	51                   	push   %ecx
 51c:	ff d0                	call   *%eax
 51e:	83 c4 10             	add    $0x10,%esp
 521:	c9                   	leave  
 522:	c3                   	ret    
 523:	90                   	nop
 524:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 528:	f3 c3                	repz ret 
 52a:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

00000530 <register_tm_clones>:
 530:	e8 a4 00 00 00       	call   5d9 <__x86.get_pc_thunk.dx>
 535:	81 c2 93 1a 00 00    	add    $0x1a93,%edx
 53b:	55                   	push   %ebp
 53c:	8d 8a 40 00 00 00    	lea    0x40(%edx),%ecx
 542:	8d 82 40 00 00 00    	lea    0x40(%edx),%eax
 548:	29 c8                	sub    %ecx,%eax
 54a:	89 e5                	mov    %esp,%ebp
 54c:	53                   	push   %ebx
 54d:	c1 f8 02             	sar    $0x2,%eax
 550:	89 c3                	mov    %eax,%ebx
 552:	83 ec 04             	sub    $0x4,%esp
 555:	c1 eb 1f             	shr    $0x1f,%ebx
 558:	01 d8                	add    %ebx,%eax
 55a:	d1 f8                	sar    %eax
 55c:	74 14                	je     572 <register_tm_clones+0x42>
 55e:	8b 92 34 00 00 00    	mov    0x34(%edx),%edx
 564:	85 d2                	test   %edx,%edx
 566:	74 0a                	je     572 <register_tm_clones+0x42>
 568:	83 ec 08             	sub    $0x8,%esp
 56b:	50                   	push   %eax
 56c:	51                   	push   %ecx
 56d:	ff d2                	call   *%edx
 56f:	83 c4 10             	add    $0x10,%esp
 572:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 575:	c9                   	leave  
 576:	c3                   	ret    
 577:	89 f6                	mov    %esi,%esi
 579:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000580 <__do_global_dtors_aux>:
 580:	55                   	push   %ebp
 581:	89 e5                	mov    %esp,%ebp
 583:	53                   	push   %ebx
 584:	e8 57 ff ff ff       	call   4e0 <__x86.get_pc_thunk.bx>
 589:	81 c3 3f 1a 00 00    	add    $0x1a3f,%ebx
 58f:	83 ec 04             	sub    $0x4,%esp
 592:	80 bb 40 00 00 00 00 	cmpb   $0x0,0x40(%ebx)
 599:	75 27                	jne    5c2 <__do_global_dtors_aux+0x42>
 59b:	8b 83 28 00 00 00    	mov    0x28(%ebx),%eax
 5a1:	85 c0                	test   %eax,%eax
 5a3:	74 11                	je     5b6 <__do_global_dtors_aux+0x36>
 5a5:	83 ec 0c             	sub    $0xc,%esp
 5a8:	ff b3 3c 00 00 00    	pushl  0x3c(%ebx)
 5ae:	e8 dd fe ff ff       	call   490 <__cxa_finalize@plt>
 5b3:	83 c4 10             	add    $0x10,%esp
 5b6:	e8 35 ff ff ff       	call   4f0 <deregister_tm_clones>
 5bb:	c6 83 40 00 00 00 01 	movb   $0x1,0x40(%ebx)
 5c2:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 5c5:	c9                   	leave  
 5c6:	c3                   	ret    
 5c7:	89 f6                	mov    %esi,%esi
 5c9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

000005d0 <frame_dummy>:
 5d0:	55                   	push   %ebp
 5d1:	89 e5                	mov    %esp,%ebp
 5d3:	5d                   	pop    %ebp
 5d4:	e9 57 ff ff ff       	jmp    530 <register_tm_clones>

000005d9 <__x86.get_pc_thunk.dx>:
 5d9:	8b 14 24             	mov    (%esp),%edx
 5dc:	c3                   	ret    

000005dd <b>:
 5dd:	55                   	push   %ebp
 5de:	89 e5                	mov    %esp,%ebp
 5e0:	53                   	push   %ebx
 5e1:	83 ec 04             	sub    $0x4,%esp
 5e4:	e8 f7 fe ff ff       	call   4e0 <__x86.get_pc_thunk.bx>
 5e9:	81 c3 df 19 00 00    	add    $0x19df,%ebx
 5ef:	83 6d 08 01          	subl   $0x1,0x8(%ebp)
 5f3:	83 7d 08 00          	cmpl   $0x0,0x8(%ebp)
 5f7:	7e 0e                	jle    607 <b+0x2a>
 5f9:	83 ec 0c             	sub    $0xc,%esp
 5fc:	ff 75 08             	pushl  0x8(%ebp)
 5ff:	e8 d9 ff ff ff       	call   5dd <b>
 604:	83 c4 10             	add    $0x10,%esp
 607:	83 ec 0c             	sub    $0xc,%esp
 60a:	8d 83 b8 e7 ff ff    	lea    -0x1848(%ebx),%eax
 610:	50                   	push   %eax
 611:	e8 3a fe ff ff       	call   450 <puts@plt>
 616:	83 c4 10             	add    $0x10,%esp
 619:	b8 00 00 00 00       	mov    $0x0,%eax
 61e:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 621:	c9                   	leave  
 622:	c3                   	ret    

00000623 <a>:
 623:	55                   	push   %ebp
 624:	89 e5                	mov    %esp,%ebp
 626:	53                   	push   %ebx
 627:	83 ec 24             	sub    $0x24,%esp
 62a:	e8 b1 fe ff ff       	call   4e0 <__x86.get_pc_thunk.bx>
 62f:	81 c3 99 19 00 00    	add    $0x1999,%ebx
 635:	83 ec 08             	sub    $0x8,%esp
 638:	ff 75 08             	pushl  0x8(%ebp)
 63b:	8d 45 d8             	lea    -0x28(%ebp),%eax
 63e:	50                   	push   %eax
 63f:	e8 fc fd ff ff       	call   440 <strcpy@plt>
 644:	83 c4 10             	add    $0x10,%esp
 647:	83 ec 0c             	sub    $0xc,%esp
 64a:	8d 83 c2 e7 ff ff    	lea    -0x183e(%ebx),%eax
 650:	50                   	push   %eax
 651:	e8 fa fd ff ff       	call   450 <puts@plt>
 656:	83 c4 10             	add    $0x10,%esp
 659:	b8 00 00 00 00       	mov    $0x0,%eax
 65e:	8b 5d fc             	mov    -0x4(%ebp),%ebx
 661:	c9                   	leave  
 662:	c3                   	ret    

00000663 <main>:
 663:	8d 4c 24 04          	lea    0x4(%esp),%ecx
 667:	83 e4 f0             	and    $0xfffffff0,%esp
 66a:	ff 71 fc             	pushl  -0x4(%ecx)
 66d:	55                   	push   %ebp
 66e:	89 e5                	mov    %esp,%ebp
 670:	53                   	push   %ebx
 671:	51                   	push   %ecx
 672:	83 ec 10             	sub    $0x10,%esp
 675:	e8 66 fe ff ff       	call   4e0 <__x86.get_pc_thunk.bx>
 67a:	81 c3 4e 19 00 00    	add    $0x194e,%ebx
 680:	83 ec 0c             	sub    $0xc,%esp
 683:	6a 00                	push   $0x0
 685:	e8 a6 fd ff ff       	call   430 <time@plt>
 68a:	83 c4 10             	add    $0x10,%esp
 68d:	83 ec 0c             	sub    $0xc,%esp
 690:	50                   	push   %eax
 691:	e8 ca fd ff ff       	call   460 <srand@plt>
 696:	83 c4 10             	add    $0x10,%esp
 699:	e8 e2 fd ff ff       	call   480 <rand@plt>
 69e:	89 45 f4             	mov    %eax,-0xc(%ebp)
 6a1:	c7 45 ee 68 65 6c 6c 	movl   $0x6c6c6568,-0x12(%ebp)
 6a8:	66 c7 45 f2 6f 00    	movw   $0x6f,-0xe(%ebp)
 6ae:	83 ec 0c             	sub    $0xc,%esp
 6b1:	8d 83 cc e7 ff ff    	lea    -0x1834(%ebx),%eax
 6b7:	50                   	push   %eax
 6b8:	e8 93 fd ff ff       	call   450 <puts@plt>
 6bd:	83 c4 10             	add    $0x10,%esp
 6c0:	8b 45 f4             	mov    -0xc(%ebp),%eax
 6c3:	83 e0 01             	and    $0x1,%eax
 6c6:	85 c0                	test   %eax,%eax
 6c8:	75 11                	jne    6db <main+0x78>
 6ca:	83 ec 0c             	sub    $0xc,%esp
 6cd:	8d 45 ee             	lea    -0x12(%ebp),%eax
 6d0:	50                   	push   %eax
 6d1:	e8 4d ff ff ff       	call   623 <a>
 6d6:	83 c4 10             	add    $0x10,%esp
 6d9:	eb 0d                	jmp    6e8 <main+0x85>
 6db:	83 ec 0c             	sub    $0xc,%esp
 6de:	6a 04                	push   $0x4
 6e0:	e8 f8 fe ff ff       	call   5dd <b>
 6e5:	83 c4 10             	add    $0x10,%esp
 6e8:	b8 00 00 00 00       	mov    $0x0,%eax
 6ed:	8d 65 f8             	lea    -0x8(%ebp),%esp
 6f0:	59                   	pop    %ecx
 6f1:	5b                   	pop    %ebx
 6f2:	5d                   	pop    %ebp
 6f3:	8d 61 fc             	lea    -0x4(%ecx),%esp
 6f6:	c3                   	ret    
 6f7:	66 90                	xchg   %ax,%ax
 6f9:	66 90                	xchg   %ax,%ax
 6fb:	66 90                	xchg   %ax,%ax
 6fd:	66 90                	xchg   %ax,%ax
 6ff:	90                   	nop

00000700 <__libc_csu_init>:
 700:	55                   	push   %ebp
 701:	57                   	push   %edi
 702:	56                   	push   %esi
 703:	53                   	push   %ebx
 704:	e8 d7 fd ff ff       	call   4e0 <__x86.get_pc_thunk.bx>
 709:	81 c3 bf 18 00 00    	add    $0x18bf,%ebx
 70f:	83 ec 0c             	sub    $0xc,%esp
 712:	8b 6c 24 28          	mov    0x28(%esp),%ebp
 716:	8d b3 04 ff ff ff    	lea    -0xfc(%ebx),%esi
 71c:	e8 d3 fc ff ff       	call   3f4 <_init>
 721:	8d 83 00 ff ff ff    	lea    -0x100(%ebx),%eax
 727:	29 c6                	sub    %eax,%esi
 729:	c1 fe 02             	sar    $0x2,%esi
 72c:	85 f6                	test   %esi,%esi
 72e:	74 25                	je     755 <__libc_csu_init+0x55>
 730:	31 ff                	xor    %edi,%edi
 732:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 738:	83 ec 04             	sub    $0x4,%esp
 73b:	55                   	push   %ebp
 73c:	ff 74 24 2c          	pushl  0x2c(%esp)
 740:	ff 74 24 2c          	pushl  0x2c(%esp)
 744:	ff 94 bb 00 ff ff ff 	call   *-0x100(%ebx,%edi,4)
 74b:	83 c7 01             	add    $0x1,%edi
 74e:	83 c4 10             	add    $0x10,%esp
 751:	39 fe                	cmp    %edi,%esi
 753:	75 e3                	jne    738 <__libc_csu_init+0x38>
 755:	83 c4 0c             	add    $0xc,%esp
 758:	5b                   	pop    %ebx
 759:	5e                   	pop    %esi
 75a:	5f                   	pop    %edi
 75b:	5d                   	pop    %ebp
 75c:	c3                   	ret    
 75d:	8d 76 00             	lea    0x0(%esi),%esi

00000760 <__libc_csu_fini>:
 760:	f3 c3                	repz ret 

Disassembly of section .fini:

00000764 <_fini>:
 764:	53                   	push   %ebx
 765:	83 ec 08             	sub    $0x8,%esp
 768:	e8 73 fd ff ff       	call   4e0 <__x86.get_pc_thunk.bx>
 76d:	81 c3 5b 18 00 00    	add    $0x185b,%ebx
 773:	83 c4 08             	add    $0x8,%esp
 776:	5b                   	pop    %ebx
 777:	c3                   	ret    
